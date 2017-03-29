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
 * This file consists of all the VFS interactions.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/mount.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/protosw.h>
#include <sys/sockopt.h>
#include <sys/socketvar.h>
#include <sys/pcpu.h>
#include <sys/proc.h>
#include <sys/vnode.h>
#include <sys/fnv_hash.h>
#include <sys/fcntl.h>
#include <sys/priv.h>
#include <geom/geom.h>
#include <geom/geom_vfs.h>
#include <sys/namei.h>

#include "virtfs_proto.h"
#include "../client.h"
#include "../9p.h"
#include "virtfs.h"

static MALLOC_DEFINE(M_P9MNT, "virtfs_mount", "Mount structures for virtfs");
uma_zone_t virtfs_node_zone;

void
dispose_node(struct virtfs_node **nodep)
{
        struct virtfs_node *node;
        struct vnode *vp;

        node = *nodep;
        if (!node)
                return;

        p9_debug(VOPS, "dispose_node: %p\n", *nodep);

        vp = NTOV(node);
        vp->v_data = NULL;

	if (!(vp->v_vflag & VV_ROOT))
		/* Free our associated memory */
		uma_zfree(virtfs_node_zone, node);

        *nodep = NULL;
}

static int
virtfs_init(struct vfsconf *vfsp)
{
        virtfs_node_zone = uma_zcreate("virtfs node zone",
            sizeof(struct virtfs_node), NULL, NULL, NULL, NULL, 0, 0);

        return (0);
}

static int
virtfs_uninit(struct vfsconf *vfsp)
{
        uma_zdestroy(virtfs_node_zone);
        return (0);
}

static int
virtfs_unmount(struct mount *mp, int mntflags)
{
	struct virtfs_mount *vmp = VFSTOP9(mp);
	int error, flags, i;

	error = 0;
	flags = 0;
	if (vmp == NULL)
		return (0);

	if (mntflags & MNT_FORCE)
		flags |= FORCECLOSE;

	/* 10 Retries ? */
	for (i = 0; i < 10; i++) {
		/* Flush everything on this mount point.
		 * This anyways doesnt do anything now.*/
		error = vflush(mp, 0, flags, curthread);
		if (error == 0 || (mntflags & MNT_FORCE) == 0)
			break;
		/* Sleep until interrupted or 1 tick expires. */
		error = tsleep(&error, PSOCK, "p9unmnt", 1);
		if (error == EINTR)
			break;
		error = EBUSY;
	}
	if (error != 0)
		goto out;

	virtfs_close_session(mp);
	/* Cleanup the mount structure. */
	free(vmp, M_P9MNT);
	mp->mnt_data = NULL;
out:
	return error;
}

/* For the root vnode's vnops. */
extern struct vop_vector virtfs_vnops;

/* This is a vfs ops routiune so defining it here instead of vnops. This
   needs some fixing(a wrapper moslty when we need create to work. Ideally
   it should call this, initialize the virtfs_node and create the fids and qids
   for interactions*/
int virtfs_vget_wrapper
        (struct mount *mp,
        struct virtfs_node *virtfs_node,
        int flags,
	struct p9_fid *fid,
        struct vnode **vpp)
{
	struct virtfs_mount *vmp;
	struct virtfs_session *p9s;
	struct vnode *vp;
	struct thread *td;
	uint32_t ino;
	struct p9_stat_dotl *st = NULL;
	int error;
	struct virtfs_inode *inode;

	td = curthread;
	vmp = VFSTOP9(mp);
	p9s = &vmp->virtfs_session;

	/* This should either be a root one or the walk on(which should have cloned)*/
	ino = fid->fid;

	error = vfs_hash_get(mp, ino, flags, td, vpp, NULL, NULL);
	if (error || *vpp != NULL)
		return (error);

	/*
	 * We must promote to an exclusive lock for vnode creation.  This
	 * can happen if lookup is passed LOCKSHARED.
 	 */
	if ((flags & LK_TYPE_MASK) == LK_SHARED) {
		flags &= ~LK_TYPE_MASK;
		flags |= LK_EXCLUSIVE;
	}

	/* Allocate a new vnode. */
	if ((error = getnewvnode("virtfs", mp, &virtfs_vnops, &vp)) != 0) {
		*vpp = NULLVP;
		return (error);
	}
	/* If we dont have it, create one. */
	if (virtfs_node == NULL) {
		// Make the virtfs_node as a zone allocator ?
		virtfs_node =  uma_zalloc(virtfs_node_zone, M_WAITOK | M_ZERO);
		inode = &virtfs_node->inode;
		vp->v_data = virtfs_node;
		/* This should be initalized in the caller of this routine */
		virtfs_node->vfid = fid;  /* Nodes fid*/
		virtfs_node->v_node = vp; /* map the vnode to ondisk*/
		virtfs_node->virtfs_ses = p9s; /* Map the current session */
		SET_LINKS(inode);
	}
	else {
		vp->v_data = virtfs_node;
		/* This should be initalized in the caller of this routine */
		virtfs_node->v_node = vp; /* map the vnode to ondisk*/
		vp->v_type = VDIR; /* root vp is a directory */
		vp->v_vflag |= VV_ROOT;
		inode = &virtfs_node->inode;
		SET_LINKS(inode);
	}
	VIRTFS_LOCK(p9s);
	/* Add the virtfs_node to the list for cleanup later.*/
	STAILQ_INSERT_TAIL(&p9s->virt_node_list, virtfs_node, virtfs_node_next);
	VIRTFS_UNLOCK(p9s);

	lockmgr(vp->v_vnlock, LK_EXCLUSIVE, NULL);
	error = insmntque(vp, mp);
	if (error != 0) {
		/* Something went wrong, dispose the node */
		dispose_node(&virtfs_node);
		*vpp = NULLVP;
		return (error);
	}
	error = vfs_hash_insert(vp, ino, flags, td, vpp, NULL, NULL);
	if (error || *vpp != NULL)
		return (error);

	if (virtfs_proto_dotl(p9s)) {
		//st = p9_client_getattr_dotl(fid, P9PROTO_STATS_BASIC);
        	if (st == NULL) {
			error = ENOMEM;
			goto out;
		}
		/* copy back the qid into the p9node also,.*/
		memcpy(&virtfs_node->vqid, &st->qid, sizeof(st->qid));

		/* Init the vnode with the disk info*/
                //virtfs_stat_vnode_l();
		/* There needs to be quite a few changes to M_TEMPS to have
		pools for each structure */
                free(st, M_TEMP);

        } else {
		/* Init the vnode with the disk info*/
                if ((error = virtfs_reload_stats(vp))) {
			goto out;
		}
	}

	*vpp = vp;
	return 0;
out:
	return error;
}

/* Main mount function for 9pfs*/
static int
p9_mount(struct mount *mp)
{
	struct p9_fid *fid;
	struct virtfs_mount *vmp = NULL;
	struct virtfs_session *p9s;
	struct virtfs_node *root;
	int error = EINVAL;

	/* Since the hardware iosize from the Qemu*/
	/* How do we get this gneric ? */
	mp->mnt_iosize_max = 4096;
	//printf("mnt_iosize :%d\n",mp->mnt_iosize_max);
	/* Allocate and initialize the private mount structure. */
	vmp = malloc(sizeof (struct virtfs_mount), M_P9MNT, M_WAITOK | M_ZERO);
	mp->mnt_data = vmp;
	vmp->virtfs_mountp = mp;
	p9s = &vmp->virtfs_session;
	p9s->virtfs_mount = mp;
	root = &p9s->rnp;

	fid = virtfs_init_session(mp);
	if (fid == NULL) {
		error = ENOMEM;
		goto out;
	}
	root->vfid = fid;
	root->virtfs_ses = p9s; /*session ptr structure .*/
	mp->mnt_stat.f_fsid.val[1] = mp->mnt_vfc->vfc_typenum;
	mp->mnt_maxsymlinklen = 0;
	MNT_ILOCK(mp);
	mp->mnt_flag |= MNT_LOCAL;
	mp->mnt_kern_flag |= MNTK_LOOKUP_SHARED | MNTK_EXTENDED_SHARED;
	MNT_IUNLOCK(mp);
	p9_debug(VFS, "Mount successful\n");
	/* Mount structures created. */

	return 0;
out:
	p9_debug(VFS, " Mount Failed \n");
	if (vmp) {
		free(vmp, M_P9MNT);
		mp->mnt_data = NULL;
	}
	return error;
}

/*
 * Mount entry point. This looks smaller compared to typical FS entry points in BSD.
 * This is a virtual device that is being mounted on so we dont really have a way to
 * check the ND and the geom permissions which are usually done here.
 */
static int
virtfs_mount(struct mount *mp)
{
	int error = 0;

	/* No support for UPDATE for now */
	if (mp->mnt_flag & MNT_UPDATE)
		return EOPNOTSUPP;

	if ((error = p9_mount(mp)))
	{
		goto out;
	}

	return 0;

out:
	if (error != 0)
		(void) virtfs_unmount(mp, MNT_FORCE);
	return (error);
}

static int
virtfs_root(struct mount *mp, int lkflags, struct vnode **vpp)
{
	struct virtfs_mount *vmp = VFSTOP9(mp);
	struct virtfs_node *np = &vmp->virtfs_session.rnp;
	int error = 0;

	if ((error = virtfs_vget_wrapper(mp, np, lkflags, np->vfid, vpp))) {

		*vpp = NULLVP;
		return error;
	}
	np->v_node = *vpp;
	vref(*vpp);

	return (error);
}

/* Get this working to fix the default sizes */
static int
virtfs_statfs(struct mount *mp, struct statfs *buf)
{
        /* For uniix version we dont need to poll the host.
         * when we add the linux version , we need to call the client
         * _statfs call
         */
        (void)mp;
        buf->f_bsize = PAGE_SIZE;
        buf->f_iosize = buf->f_bsize;

        return 0;
}

static int
virtfs_fhtovp(struct mount *mp, struct fid *fhp, int flags, struct vnode **vpp)
{
	return (EINVAL);
}

static int
virtfs_sync(struct mount *mp, int waitfor)
{
	return (0);
}

struct vfsops virtfs_vfsops = {
	.vfs_init  =	virtfs_init,
	.vfs_uninit = 	virtfs_uninit,
	.vfs_mount =	virtfs_mount,
	.vfs_unmount =	virtfs_unmount,
	.vfs_root =	virtfs_root,
	.vfs_statfs =	virtfs_statfs,
	.vfs_fhtovp =	virtfs_fhtovp,
	.vfs_sync =	virtfs_sync,
	.vfs_vget = NULL, //    virtfs_vget,
};
VFS_SET(virtfs_vfsops, virtfs, VFCF_JAIL);
MODULE_VERSION(vtfs, 1);
MODULE_DEPEND(vtfs, virtio, 1, 1, 1);
MODULE_DEPEND(vtfs, vt9p, 1, 1, 1);
