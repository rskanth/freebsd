/*-
 * Copyright (c) 2016 Raviprakash Darbha
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */
/*
 * The Virtio 9p transport driver
 */

#include <sys/errno.h>
#include "../9p.h"
#include "../client.h"
#include "transport.h"
#include "../protocol.h"

#include <sys/module.h>
#include <sys/sglist.h>
#include <sys/queue.h>
#include <sys/bus.h>
#include <sys/kthread.h>
#include <machine/bus.h>

#include <dev/virtio/virtio.h>
#include <dev/virtio/virtqueue.h>
#include <dev/virtio/virtio_ring.h>
#include <sys/condvar.h>

#define VIRTQUEUE_NUM	128
#define VT9P_MTX(_sc) &(_sc)->vt9p_mtx
#define VT9P_LOCK(_sc) mtx_lock(VT9P_MTX(_sc))
#define VT9P_UNLOCK(_sc) mtx_unlock(VT9P_MTX(_sc))
#define VT9P_LOCK_INIT(_sc) mtx_init(VT9P_MTX(_sc), "VIRTIO 9P CHAN lock", NULL, MTX_DEF)
#define VT9P_LOCK_DESTROY(_sc) mtx_destroy(VT9P_MTX(_sc))
#define MAX_SUPPORTED_SGS 20
struct virtqueue;

/* We can move this to a new header later if we need.
 * For now we re the only ones using this struct .
 */
struct vt9p_softc {
	device_t vt9p_dev;
	struct mtx vt9p_mtx;
	struct sglist *vt9p_sglist;
	struct cv  submit_cv;
	struct mtx submit_cv_lock;
	struct p9_client *client;
	struct virtqueue *vt9p_vq;
	int max_nsegs;
};

/* We don't currently allow canceling of virtio requests */
static int vt9p_cancel(struct p9_client *client, struct p9_req_t *req)
{
	return 1;
}

static int
vt9p_request(struct p9_client *client, struct p9_req_t *req)
{
	int err;
	struct vt9p_softc *chan = client->trans;
	void *c = NULL;
	int readable = 0, writable = 0;
	struct sglist *sg;
	struct virtqueue *vq;

	sg = chan->vt9p_sglist;
	vq = chan->vt9p_vq;

	p9_debug(TRANS, "9p debug: virtio request\n");


	/* Grab the channel lock*/
	VT9P_LOCK(chan);

	sglist_reset(sg);
	/* Handle out VirtIO ring buffers */
	err = sglist_append(sg, req->tc->sdata, req->tc->size);
	if (err < 0) {
		printf("Something wrong with sglist append ..\n");	
		return err;
	}
	readable = sg->sg_nseg;

	err = sglist_append(sg, req->rc->sdata, req->rc->capacity);
	if (err < 0) {
		printf("Something wrong with sglist append ..\n");	
		return err;
	}
	writable = sg->sg_nseg - readable;
	
	//virtqueue_dump(vq);
req_retry:
	err = virtqueue_enqueue(vq, req, sg, readable, writable);

	//virtqueue_dump(vq);

	if (err < 0) {
		if (err == ENOSPC) {
			/* Condvar for the submit queue. Can we still hold chan lock ?*/
			cv_wait(&chan->submit_cv, &chan->submit_cv_lock);
			p9_debug(TRANS, "Retry virtio request\n");
			goto req_retry;
		} else {
			p9_debug(TRANS,
				 "virtio rpc add_sgs returned failure\n");
			return EIO;
		}
	}

	/* We have to notify */
	virtqueue_notify(vq);
	while((c = virtqueue_dequeue(vq, NULL)) == NULL)
	 	msleep(chan, VT9P_MTX(chan), 0, "chan lock", 0);
        VT9P_UNLOCK(chan);

	//virtqueue_dump(vq);
	p9_debug(TRANS, "virtio request kicked\n");
	return 0;
}

/* Completion of the request from the virt queue. */
static void
vt9p_intr_complete(void *xsc)
{
	struct vt9p_softc *chan;
	chan = (struct vt9p_softc *)xsc;
	struct virtqueue *vq = chan->vt9p_vq;

	p9_debug(TRANS, "Completing iinterrupt \n");

        VT9P_LOCK(chan);
	virtqueue_enable_intr(vq);
        wakeup(chan);
        VT9P_UNLOCK(chan);
}

static int
vt9p_alloc_virtqueue(struct vt9p_softc *sc)
{
	struct vq_alloc_info vq_info;
	device_t dev = sc->vt9p_dev;

	VQ_ALLOC_INFO_INIT(&vq_info, sc->max_nsegs,
		vt9p_intr_complete, sc, &sc->vt9p_vq,
		"%s request", device_get_nameunit(dev));

	return (virtio_alloc_virtqueues(dev, 0, 1, &vq_info));
}

static int
vt9p_probe(device_t dev)
{
	/* VIRTIO_ID_9P is already defined */
	if (virtio_get_device_type(dev) != VIRTIO_ID_9P)
		return (ENXIO);
    	device_set_desc(dev, "VirtIO 9P Transport");
    	p9_debug(TRANS, "Probe successful .\n");

    	return (BUS_PROBE_DEFAULT);
}

static void
vt9p_stop(struct vt9p_softc *sc)
{
	/* Device specific stops .*/
        virtqueue_disable_intr(sc->vt9p_vq);
        virtio_stop(sc->vt9p_dev);
}

static int
vt9p_detach(device_t dev)
{
	struct vt9p_softc *sc;
        sc = device_get_softc(dev);

        VT9P_LOCK(sc);
        vt9p_stop(sc);
        VT9P_UNLOCK(sc);

	if (sc->vt9p_sglist) {
		sglist_free(sc->vt9p_sglist);
                sc->vt9p_sglist = NULL;
	}
	VT9P_LOCK_DESTROY(sc);

        return (0);
}

struct vt9p_softc *global_ctx;
static int vt9p_attach(device_t dev)
{
	int err;
	struct vt9p_softc *chan;

	chan = device_get_softc(dev);
	chan->vt9p_dev = dev;

	/* Init the channel lock. */
	VT9P_LOCK_INIT(chan);

	/* Ideally we would want to calculate the number of segements
	 * from the configuration but for now, Well just make it 
	 * 20segs. Refer to virtio_block for this number.
	 */
	chan->max_nsegs = MAX_SUPPORTED_SGS;
	chan->vt9p_sglist = sglist_alloc(chan->max_nsegs, M_NOWAIT);

	if (chan->vt9p_sglist == NULL) {
		err = ENOMEM;
		p9_debug(TRANS, "Cannot allocate sglist\n");
		goto out;
	}

	/* This is the mount tag for now. Qemu server has to export the device using this mount	
	 * tag.*/
	/* /usr/bin/qemu-kvm -m 1024 -name f15 -drive file=/images/f15.img,if=virtio
	 * -fsdev local,security_model=passthrough,id=fsdev0,path=/tmp/share -device virtio-9p-pci,
	 * id=fs0,fsdev=fsdev0,mount_tag=hostshare
	 */

	/* We expect one virtqueue, for requests. */
	err = vt9p_alloc_virtqueue(chan);

	if (err < 0) {
		p9_debug(TRANS, "Allocating the virtqueue failed \n");
		goto out;
	}

	err = virtio_setup_intr(dev, INTR_TYPE_MISC|INTR_MPSAFE);
	if (err) {
		p9_debug(TRANS, "Cannot setup virtqueue interrupt\n");
		goto out;
	}
	err = virtqueue_enable_intr(chan->vt9p_vq);

	if (err) {
		p9_debug(TRANS, "Cannot enable virtqueue interrupt\n");
		goto out;
	}

	/* We have only one global channel for now.*/
	global_ctx = chan;
	p9_debug(TRANS, "Attach successfully \n");
	return 0;

out:
	/* Something went wrong, detach the device */
	vt9p_detach(dev);
	return err;
}

static int
vt9p_create(struct p9_client *client)
{
	struct vt9p_softc *chan = NULL;

	if (global_ctx)
	chan = global_ctx;

	/* If we dont have one, for now bail out.*/
	if (chan) {
		client->trans = (void *)chan;
		chan->client = client;
	}
	else {
		p9_debug(TRANS, "No Global channel. Others not supported yet \n");
		return -1;
	}

	return 0;
}

static struct p9_trans_module vt9p_trans = {
	.name = "virtio",
	.create = vt9p_create,
	.request = vt9p_request,
	.cancel = vt9p_cancel,
	.def = 1,
};

struct p9_trans_module *p9_get_default_trans(void)
{
	return &vt9p_trans;

}

void p9_put_trans(struct p9_trans_module *m)
{
	printf("%s: its just a stub now\n", __func__);
}


static device_method_t vt9p_mthds[] = {
    /* Device methods. */
    DEVMETHOD(device_probe,     vt9p_probe),
    DEVMETHOD(device_attach,    vt9p_attach),
    DEVMETHOD(device_detach,    vt9p_detach),
    DEVMETHOD_END
};

static driver_t vt9p_drv = {
    "9p_virtio",
    vt9p_mthds,
    sizeof(struct vt9p_softc)
};
static devclass_t vt9p_class;

static int
vt9p_modevent(module_t mod, int type, void *unused)
{
    int error = 0;

    switch (type) {
        case MOD_LOAD: {
            break;
        }
        case MOD_UNLOAD: {
            break;
        }
        case MOD_SHUTDOWN:
            break;
        default:
            error = EOPNOTSUPP;
            break;
    }
    return (error);
}

DRIVER_MODULE(vt9p, virtio_pci, vt9p_drv, vt9p_class,
	vt9p_modevent, 0);
MODULE_VERSION(vt9p, 1);
MODULE_DEPEND(vt9p, virtio, 1, 1, 1);
