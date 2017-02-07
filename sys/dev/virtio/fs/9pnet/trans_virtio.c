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
//#define VT9P_INIT(mtx)
struct virtqueue;

/* a single mutex to manage channel initialization and attachment */
//struct mtx virtio_9p_lock;

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
	int ring_bufs_avail;
	int max_nsegs;
	int inuse;
	int chan_name_len;
	char *chan_name;
};

//static SLIST_HEAD (,vt9p_softc) vt9p_softc_list;


static void vt9p_close(struct p9_client *client)
{
	struct vt9p_softc *chan = client->trans;

//	mtx_lock(&virtio_9p_lock);
	if (chan)
		chan->inuse = false;

//	mtx_unlock(&virtio_9p_lock);
}

/* We don't currently allow canceling of virtio requests */
static int vt9p_cancel(struct p9_client *client, struct p9_req_t *req)
{
	return 1;
}


# if 0
 device_t                 vq_dev;
58        char                     vq_name[VIRTQUEUE_MAX_NAME_SZ];
59        uint16_t                 vq_queue_index;
60        uint16_t                 vq_nentries;
61        uint32_t                 vq_flags;
62#define VIRTQUEUE_FLAG_INDIRECT  0x0001
63#define VIRTQUEUE_FLAG_EVENT_IDX 0x0002
64
65        int                      vq_alignment;
66        int                      vq_ring_size;
67        void                    *vq_ring_mem;
68        int                      vq_max_indirect_size;
69        int                      vq_indirect_mem_size;
70        virtqueue_intr_t        *vq_intrhand;
71        void                    *vq_intrhand_arg;
72
73        struct vring             vq_ring;
74        uint16_t                 vq_free_cnt;
75        uint16_t                 vq_queued_cnt;
76   
    */
81        uint16_t                 vq_desc_head_idx;
82        /*
83         * Last consumed descriptor in the used table,
84         * trails vq_ring.used->idx.
85         */
86        uint16_t                 vq_used_cons_idx;
87
#endif 

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
	req->status = REQ_STATUS_SENT;

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
	
	virtqueue_dump(vq);
req_retry:
	err = virtqueue_enqueue(vq, req, sg, readable, writable);

	virtqueue_dump(vq);
        chan->ring_bufs_avail--;
	/* Retry mechanism for the requeue. We could either
	 * do it this way - Where we sleep in this context and
	 * wakeup again when we have resources or create a new
	 * queue to enqueue and return back. */
	if (err < 0) {
		if (err == ENOSPC) {
			chan->ring_bufs_avail = 0;
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

	virtqueue_dump(vq);
	p9_debug(TRANS, "virtio request kicked\n");
	return 0;
}

#if 0
  if (vq->vq_flags & VIRTQUEUE_FLAG_EVENT_IDX)
                vring_used_event(&vq->vq_ring) = vq->vq_used_cons_idx + ndesc;
        else
                vq->vq_ring.avail->flags &= ~VRING_AVAIL_F_NO_INTERRUPT;

        mb();
#endif
#define VIRTQUEUE_FLAG_EVENT_IDX 0x0002
#define VRING_AVAIL_F_NO_INTERRUPT 1
/* Completion of the request from the virt queue. */
static void
vt9p_intr_complete(void *xsc)
{
	#if 0
	struct virtqueue *vq;
	struct p9_req_t *req;
	//struct req_queue queue;
	printf("intr handler has to hit.. \n");
	vq = chan->vt9p_vq;

        /* Ideally we should be running the loop and copying
        all the completed requests into a stack queue and co
        mplte to the upper layers. For now, we are only fini*/
   	//while (1) {
		VT9P_LOCK(chan);
		req = virtqueue_dequeue(chan->vt9p_vq, NULL);
	/*	if (req == NULL) {
			VT9P_UNLOCK(chan);
			break;
		} */
	//}
 	VT9P_UNLOCK(chan);
	/* Wakeup if anyone waiting for VirtIO ring space. */
	cv_signal(&chan->submit_cv);
	p9_client_cb(chan->client, req);
	#endif
	struct vt9p_softc *chan;
	chan = (struct vt9p_softc *)xsc;
	struct virtqueue *vq = chan->vt9p_vq;

	printf("completing the interrupt ..\n");

        VT9P_LOCK(chan);
	chan->ring_bufs_avail++;
	// dont forget to enable intr.
	// SOmething is messed up here.. come back and fix this.
	/// for now i am just clearing the bit.
	//dirty hack for now.
	//vq->vq_flags &= ~VIRTQUEUE_FLAG_EVENT_IDX;
	if (virtqueue_enable_intr(vq) != 0) {
		//virtqueue_disable_intr(vq);
		printf("intere:");
	}

	// Set it back
	//vq->vq_flags |= VIRTQUEUE_FLAG_EVENT_IDX;

        wakeup(chan);
        VT9P_UNLOCK(chan);
}


#if 0 /* This will be uncommented when we run in queue */
gain:
	//p9_queue_completed(chan, &queue);

	p9_client_cb(chan, req); 
	// check if we need to start ?
	if (virtqueue_enable_intr(vq) != 0) {
		virtqueue_disable_intr(vq);
		goto again;
	}

	// Signal for submit queue.
//out:
	//p9_done_completed(chan, &queue);
}
#endif 

static int vt9p_alloc_virtqueue(struct vt9p_softc *sc)
{
    
	struct vq_alloc_info vq_info;
	device_t dev = sc->vt9p_dev;

	VQ_ALLOC_INFO_INIT(&vq_info, sc->max_nsegs,
		vt9p_intr_complete, sc, &sc->vt9p_vq,
		"%s request", device_get_nameunit(dev));

	return (virtio_alloc_virtqueues(dev, 0, 1, &vq_info));
}

static 
int vt9p_probe(device_t dev)
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
vt9p_remove(struct vt9p_softc *chan)
{
	//mtx_lock(&virtio_9p_lock);

	/* Remove self from list so we don't get new users. */
	//SLIST_REMOVE(&vt9p_softc_list, chan, vt9p_softc, chan_list);

	/* Wait for existing users to close. 
	while (chan->inuse) {
		mtx_unlock(&virtio_9p_lock);
		msleep(250);
		mtx_lock(&virtio_9p_lock);
	}
	*/
	chan->inuse = false; 
	//mtx_unlock(&virtio_9p_lock);

	// AGain call the vq deletion here otherwise it might leak.

	free(chan->chan_name, M_TEMP);
	return 0;
}

static int
vt9p_detach(device_t dev)
{
	struct vt9p_softc *sc;
        sc = device_get_softc(dev);

        VT9P_LOCK(sc);
        vt9p_stop(sc);
        VT9P_UNLOCK(sc);

        vt9p_remove(sc);

	if (sc->vt9p_sglist) {
		sglist_free(sc->vt9p_sglist);
                sc->vt9p_sglist = NULL;
	}
	VT9P_LOCK_DESTROY(sc);

        return (0);
}

struct vt9p_softc *global_ctx; // For now.. theres only one channel
static int vt9p_attach(device_t dev)
{
	uint16_t name_len;
	int err;
	struct vt9p_softc *chan;

	chan = device_get_softc(dev);
	chan->vt9p_dev = dev;

	/* Init the channel lock. */
	VT9P_LOCK_INIT(chan);
	/* this lock is for the chan selection in create
	 * that is still not functional now but just init the lock */
	//VT9P_INIT(virtio_9p_lock);

	/* Ideally we would want to calculate the number of segements
	 * from the configuration but for now, Well just make it 
	 * 20segs. Refer to virtio_block for this number.
	 */
	chan->max_nsegs = 20;
	chan->vt9p_sglist = sglist_alloc(chan->max_nsegs, M_NOWAIT);

	if (chan->vt9p_sglist == NULL) {
		err = ENOMEM;
		printf("cannot allocate sglist\n");
		goto out;
	}

	chan->inuse = false;
	/* This is the mount tag for now. Qemu server has to export the device using this mount	
	 * tag.*/
	/* /usr/bin/qemu-kvm -m 1024 -name f15 -drive file=/images/f15.img,if=virtio
	 * -fsdev local,security_model=passthrough,id=fsdev0,path=/tmp/share -device virtio-9p-pci,
	 * id=fs0,fsdev=fsdev0,mount_tag=hostshare
	 */
	name_len = strlen("hostshare");
	chan->chan_name = malloc(name_len, M_TEMP,  M_WAITOK | M_ZERO);
	if (!chan->chan_name) {
		err = ENOMEM;
		goto out;
	}

	chan->chan_name_len = name_len;
	chan->chan_name ="hostshare";

	// Add to this wait queue which will later be woken up.
	///TAILQ_INIT(&chan->vc_wq);
	chan->ring_bufs_avail = 5;

	// Add all of them to the channel list so that we can create(mount) only to one.
	//mtx_lock(&virtio_9p_lock);
	//SLIST_INSERT_TAIL(&chan->chan_list, &vt9p_softc_list);
	//mtx_unlock(&virtio_9p_lock);

	/* We expect one virtqueue, for requests. */
	err = vt9p_alloc_virtqueue(chan);

	if (err < 0) {
		printf("allocating the virtqueue failed ..\n");
		goto out;
	}

	err = virtio_setup_intr(dev, INTR_TYPE_MISC|INTR_MPSAFE);
	if (err) {
		printf("cannot setup virtqueue interrupt\n");
		goto out;
	}
	err = virtqueue_enable_intr(chan->vt9p_vq);
	
	if (err) {
		printf("cannot enable virtqueue interrupt\n");
		goto out;
	}

	global_ctx = chan;
	p9_debug(TRANS, "Attach successfully \n"); 
	return 0;

out:
	free(chan->chan_name, M_TEMP);

	/* Something went wrong, detach the device */
	vt9p_detach(dev);
	return err;
}


/**
 * vt9p_create - allocate a new virtio channel
 * @client: client instance invoking this transport
 * @devname: string identifying the channel to connect to (unused)
 * @args: args passed from sys_mount() for per-transport options (unused)
 *
 * This sets up a transport channel for 9p communication.  Right now
 * we only match the first available channel, but eventually we couldlook up
 * alternate channels by matching devname versus a virtio_config entry.
 * We use a simple reference count mechanism to ensure that only a single
 * mount has a channel open at a time.
 *
 */

static int
vt9p_create(struct p9_client *client)
{
	struct vt9p_softc *chan =NULL;
	//int ret = -ENOENT;
	//int found = 0;

	//mtx_lock(&virtio_9p_lock);
	/*STAILQ_FOREACH(chan, &vt9p_softc_list, chan_list) {
		if (!strncmp(devname, chan->chan_name, chan->chan_name_len) &&
		    strlen(devname) == chan->chan_name_len) {
			if (!chan->inuse) {
				chan->inuse = true;
				found = 1;
				break;
			}
			ret = -EBUSY;
		}
	}*/
	// This hack will be cleaned up after POC with SLISTs.
	if (global_ctx)
	chan = global_ctx;

	//mtx_unlock(&virtio_9p_lock);

	/*if (!found) {
		printf("no channels available for device %s\n", client->name);
		return ret;
	}*/

	client->trans = (void *)chan;
	client->status = Connected;
	chan->client = client;

	return 0;
}

static struct p9_trans_module vt9p_trans = {
	.name = "virtio",
	.create = vt9p_create,
	.close = vt9p_close,
	.request = vt9p_request,
	.cancel = vt9p_cancel,
	.def = 1,
};

// move it to mod.c after POC and then get the list setting right later.
struct p9_trans_module *p9_get_trans_by_name(char *s)
{
	//struct p9_trans_module *t, *found = NULL;

	//mtx_lock_spin(&v9fs_trans_lock);
	(void)s;

	/*STAILQ_FOREACH(t, &v9fs_trans_list, list) {
		if (strcmp(t->name, s) == 0 ) {
			found = t;
			break;
		}
	}*/

	//mtx_unlock_spin(&v9fs_trans_lock);
	return &vt9p_trans;
	//return found;
}

struct p9_trans_module *p9_get_default_trans(void)
{
	printf("%s: XXX not implemented\n", __func__);
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
            //INIT_LIST_HEAD(&vt9p_softc_list);
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
