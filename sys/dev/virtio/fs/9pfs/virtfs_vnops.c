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

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/vnode.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <sys/malloc.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/dirent.h>
#include <sys/namei.h>
#include <sys/stat.h>

#include <sys/types.h>
#include <fcntl.h>
#include "virtfs_proto.h"
#include "virtfs.h"
#include "../client.h"

#include <vm/vm.h>
#include <vm/vm_extern.h>
#include <vm/vm_object.h>
#include <vm/vnode_pager.h>

struct vop_vector virtfs_vnops;
uint32_t convert_to_p9_mode(uint32_t mode);

static int
virtfs_cleanup(struct virtfs_node *node)
{
	struct vnode *vp = NTOV(node);
	/* Invalidate all entries to a particular vnode. */
        cache_purge(vp);

        /* Destroy the vm object and flush associated pages. */
        vnode_destroy_vobject(vp);
	vfs_hash_remove(vp);

        /* Dispose all node knowledge.*/
       	dispose_node(&node);
	return 0;
}

static int
virtfs_reclaim(struct vop_reclaim_args *ap)
{
        struct vnode *vp = ap->a_vp;
        struct virtfs_node *virtfs_node = VTON(vp);

        p9_debug(VOPS, "%s: vp:%p node:%p\n", __func__, vp, virtfs_node);
	if (virtfs_node == NULL) return 0;

	if (virtfs_node->vfid)
		p9_client_clunk(virtfs_node->vfid);

	virtfs_cleanup(virtfs_node);
        return (0);
}

static int
virtfs_lookup(struct vop_cachedlookup_args *ap)
{
	/* direnode */
	struct vnode *dvp = ap->a_dvp;
	struct vnode **vpp = ap->a_vpp, *vp;
	struct componentname *cnp = ap->a_cnp;
	struct virtfs_node *dnp = VTON(dvp); /*dir p9_node */
	struct virtfs_session *p9s = dnp->virtfs_ses;
	struct mount *mp = p9s->virtfs_mount; /* Get the mount point */
	struct p9_fid *newfid = NULL;
	int error = 0, nameiop, islastcn;
	nameiop = cnp->cn_nameiop;
	islastcn = cnp->cn_flags & ISLASTCN;

	*vpp = NULL;

	p9_debug(VOPS,"lookup\n");
	/* Special case: lookup a directory from itself. */
	if (cnp->cn_namelen == 1 && *cnp->cn_nameptr == '.') {
		*vpp = dvp;
		vref(*vpp);
	}
	else {

		/* client_walk is equivalent to searching a component name in a directory(fid)
		 * here. If newfid is returned, we have found an entry for this component name
		 * so, go and create the rest of the vnode infra(vget_wrapper) for the returned 
		 * newfid */

		newfid = p9_client_walk(dnp->vfid,
	    		1, &cnp->cn_nameptr, 1);
		if (newfid != NULL) {
			int ltype = 0;

			if (cnp->cn_flags & ISDOTDOT) {
				vhold(dvp);
				ltype = VOP_ISLOCKED(dvp);
				VOP_UNLOCK(dvp, 0);
			}
			/* Vget gets the vp for the newly created vnode. Stick it to the virtfs_node too*/
			error = virtfs_vget_wrapper(mp, NULL, cnp->cn_lkflags, newfid, &vp);

			if (error)
				return error;
			if (cnp->cn_flags & ISDOTDOT) {
				vn_lock(dvp, ltype | LK_RETRY);
				vdrop(dvp);
			}

			*vpp = vp;
			vref(*vpp);
		}
		else {
			/* Not found return NOENTRY.*/
			error = ENOENT;
                        if ((nameiop == CREATE || nameiop == RENAME) &&
                            islastcn) {
                                error = VOP_ACCESS(dvp, VWRITE, cnp->cn_cred, cnp->cn_thread);
                                if (!error) {
                                        /* keep the component name */
                                        cnp->cn_flags |= SAVENAME;
                                        error = EJUSTRETURN;
                                }
                        }
		}
	}
	/* Store the result the the cache if MAKEENTRY is specified in flags */
	if ((cnp->cn_flags & MAKEENTRY) != 0)
		cache_enter(dvp, *vpp, cnp);	

	return (error);
}

static int
create_wrapper(struct virtfs_node *dir_node, 
	struct componentname *cnp, char *extension, uint32_t perm, uint8_t mode,
	struct vnode **vpp)
{
        int err;
        char *name = cnp->cn_nameptr;
        struct p9_fid *ofid, *newfid;
	struct virtfs_session *ses = dir_node->virtfs_ses;
	struct mount *mp = ses->virtfs_mount; 

        p9_debug(VOPS, "name %pd\n", name);

        err = 0;
        ofid = NULL;
        newfid = NULL;

	/* Same way as open, we have to walk to create a clone and
	 * use to open the dierctory.*/

	if (dir_node->vofid == NULL) {

		dir_node->vofid = p9_client_walk(dir_node->vfid,
		     0, NULL, 1); /* Clone the fid here.*/
		if (dir_node->vofid == NULL) {
			err = ENOMEM;
			goto out;
		}
	}
	ofid = dir_node->vofid;

        err = p9_client_file_create(ofid, name, perm, mode, extension);
        if (err) {
                p9_debug(VOPS, "p9_client_fcreate failed %d\n", err);
                goto out;
        }
	
	/*
	 * Do the lookup part and add the vnode, virtfs_node. Note that vpp 
	 * is filled in here.
	 */

	newfid = p9_client_walk(dir_node->vfid, 1, &name, 1);
	if (newfid != NULL) {
			err = virtfs_vget_wrapper(mp, NULL, cnp->cn_lkflags, newfid, vpp);
			if (err)
				goto out;
	}
	else {
		/* Not found return NOENTRY.*/
		err = ENOENT;
		goto out;
	}

        if ((cnp->cn_flags & MAKEENTRY) != 0)
                cache_enter(NTOV(dir_node), *vpp, cnp);
    
        p9_debug(VOPS, "created file under vp %p node %p fid %d\n", *vpp, dir_node,
            (uintmax_t)dir_node->vfid->fid);
	// Clunk the open ofid.
	if (ofid) {
                p9_client_clunk(ofid);
		dir_node->vofid = NULL;
	}

        return 0;
out:
        if (ofid)
                p9_client_clunk(ofid);

        if (newfid)
                p9_client_clunk(newfid);

        return err;
}

static int
virtfs_create(struct vop_create_args *ap)
{
	struct vnode *dvp = ap->a_dvp;
        struct vnode **vpp = ap->a_vpp;
        struct componentname *cnp = ap->a_cnp;
        uint16_t mode = MAKEIMODE(ap->a_vap->va_type, ap->a_vap->va_mode);
        struct virtfs_node *dir_node = VTON(dvp);
	uint32_t perm;
        int ret = 0;

        p9_debug(VOPS, "%s: dvp %p\n", __func__, dvp);

        perm = convert_to_p9_mode(mode);

        ret = create_wrapper(dir_node, cnp, NULL, perm, P9PROTO_ORDWR, vpp);
                
	return ret;
}

static int
virtfs_mkdir(struct vop_mkdir_args *ap)
{
	struct vnode *dvp = ap->a_dvp;
        struct vnode **vpp = ap->a_vpp;
        struct componentname *cnp = ap->a_cnp;
        uint16_t mode = MAKEIMODE(ap->a_vap->va_type, ap->a_vap->va_mode);
        struct virtfs_node *dir_node = VTON(dvp);
	uint32_t perm;
        int ret = 0;

        p9_debug(VOPS, "%s: dvp %p\n", __func__, dvp);

        perm = convert_to_p9_mode(mode | S_IFDIR);

        ret = create_wrapper(dir_node, cnp, NULL, perm, P9PROTO_ORDWR, vpp);

	return ret;
}

static int
virtfs_mknod(struct vop_mknod_args *ap)
{
	p9_debug(VOPS, "mknod");

	return 0;
}

static int virtfs_uflags_mode(int uflags, int extended)
{
        int ret;

        ret = 0;

	/* Convert first to O flags.*/
	// Can this be shorted to use Fflags directly. ?
	uflags = OFLAGS(uflags);

        switch (uflags&3) {

        case O_RDONLY:
                ret = P9PROTO_OREAD;
                break;

        case O_WRONLY:
                ret = P9PROTO_OWRITE;
                break;

        case O_RDWR:
                ret = P9PROTO_ORDWR;
                break;
        }

        if (extended) {
                if (uflags & O_EXCL)
                        ret |= P9PROTO_OEXCL;

                if (uflags & O_APPEND)
                        ret |= P9PROTO_OAPPEND;
        }

        return ret;
}

static int
virtfs_open(struct vop_open_args *ap)
{
	int error = 0;
	struct virtfs_node *np = VTON(ap->a_vp);
	struct p9_fid *fid = np->vfid;
	size_t filesize;
	int mode;

	p9_debug(VOPS, "open \n");

	if (np->v_opens > 0) {
		np->v_opens++;
		return (0);
	}

	// do we need to reload again ?
	error = virtfs_reload_stats(ap->a_vp);
	if (error != 0)
		return (error);

	/* According to 9p protocol, we cannot do Fileops on an already opened
	 * file. So we have to clone a new fid by walking and then use the open fids
	 * to do the open.
	 */
	if (np->vofid == NULL) {

		/*ofid is the open fid for this file.*/
		/* Note: Client_walk returns struct p9_fid* */
		np->vofid = p9_client_walk(np->vfid,
		     0, NULL, 1); /* Clone the fid here.*/
		if (np->vofid == NULL) {
			return ENOMEM;
		}
	}
	fid = np->vofid;
	filesize = np->inode.i_size;
	mode = virtfs_uflags_mode(ap->a_mode, 1);

	error = p9_client_open(fid, mode);
	if (error == 0) {
		np->v_opens = 1;
		vnode_create_vobject(ap->a_vp, filesize, ap->a_td);
	}

	return (error);
}

static int
virtfs_close(struct vop_close_args *ap)
{
	struct virtfs_node *np = VTON(ap->a_vp);
	
	if (np == NULL) {
		return 0;
	}

	p9_debug(VOPS,"%s(fid %d opens %d)\n", __func__,
	    np->vfid->fid, np->v_opens);
	np->v_opens--;
	if (np->v_opens == 0) {
		/* clean up the open fid */
		p9_client_clunk(np->vofid);
		np->vofid = NULL;
	}

	return (0);
}

static int
check_possible(struct vnode *vp, struct vattr *vap, mode_t mode)
{

 	/* Check if we are allowed to write */
        switch (vap->va_type) {
        case VDIR:
        case VLNK:
        case VREG:
                /*
                 * Normal nodes: check if we're on a read-only mounted
                 * filingsystem and bomb out if we're trying to write.
                 */
                if ((mode & VMODIFY_PERMS) && (vp->v_mount->mnt_flag & MNT_RDONLY))
                        return (EROFS);
                break;
        case VBLK:
        case VCHR:
        case VSOCK:
        case VFIFO:
                /*
                 * Special nodes: even on read-only mounted filingsystems
                 * these are allowed to be written to if permissions allow.
                 */
                break;
        default:
                /* No idea what this is */
                return (EINVAL);
        }

        return (0);
}

static int
virtfs_access(struct vop_access_args *ap)
{
        struct vnode *vp = ap->a_vp;
        accmode_t accmode = ap->a_accmode;
        struct ucred *cred = ap->a_cred;
        struct vattr vap;
        int error;

        p9_debug(VOPS,"virtfs_access \n");

	/* make sure getattr is working correctly and is defined.*/
        error = VOP_GETATTR(vp, &vap, NULL);
        if (error)
                return (error);

        error = check_possible(vp, &vap, accmode);
        if (error)
                return (error);

	/* Call the Generic Access check in VOPS*/
        error = vaccess(vp->v_type, vap.va_mode, vap.va_uid, vap.va_gid, accmode,
            cred, NULL);

	return error;
}

int
virtfs_reload_stats(struct vnode *vp)
{
	struct p9_wstat *st = NULL;
	int error = 0;
    	struct virtfs_node *node = VTON(vp);

	st = p9_client_stat(node->vfid);

	if (st == NULL) {
		error = ENOMEM;
		goto out;
	}

	memcpy(&node->vqid, &st->qid, sizeof(st->qid));
	/* Init the vnode with the disk info*/
	virtfs_stat_vnode_u(st, vp);
	free(st, M_TEMP);
out:
	return error;
}

static int
virtfs_getattr(struct vop_getattr_args *ap)
{
  	struct vnode *vp = ap->a_vp;
        struct vattr *vap = ap->a_vap;
        struct virtfs_node *node = VTON(vp);
        struct virtfs_inode *inode = &node->inode;
	int error = 0;

	p9_debug(VOPS, "getattr %u %u\n",inode->i_mode,IFTOVT(inode->i_mode));
 
	/* Reload our stats once to get the right values.*/
	error = virtfs_reload_stats(vp);
	if (error)
		return error;

	/* Basic info */
        VATTR_NULL(vap);

	vap->va_atime.tv_sec = inode->i_atime;
        vap->va_mtime.tv_sec = inode->i_mtime;
        vap->va_type = IFTOVT(inode->i_mode);
        vap->va_mode = inode->i_mode;
        vap->va_uid = inode->n_uid;
        vap->va_gid = inode->n_gid;
        vap->va_fsid = vp->v_mount->mnt_stat.f_fsid.val[0];
        vap->va_size = inode->i_size;
        vap->va_gen = 0;
        vap->va_filerev = 0;
        vap->va_vaflags = 0;

	return error;
}

#if 0
static void
dump_inode(struct virtfs_inode *inode)
{
	printf(">>>>>INODE DUMP \n");	

	printf("inode->size :%hhu \n",inode->i_size);	
	printf("inode->type :%hhu \n",inode->i_type);	
	printf("inode->mode :%u \n",inode->i_mode);	
	printf("inode->atime:%u \n",inode->i_atime);	
	printf("inode->mtime:%u \n",inode->i_mtime);	
	printf("inode->name :%s \n",inode->i_name);	
	printf("inode->uid  :%s \n",inode->i_uid);	
	printf("inode->gid :%s \n",inode->i_gid);	
	printf("inode->n_uid :%u \n",inode->n_uid);	
	printf("inode->n_gid :%u \n",inode->n_gid);	
}

static void
dump_stat(struct p9_wstat *stat)
{
	printf(">>>>>STAT DUMP \n");	

	printf("stat->size :%hhu \n",stat->size);	
	printf("stat->type :%hhu \n",stat->type);	
	printf("stat->mode :%u \n",stat->mode);	
	printf("stat->atime:%u \n",stat->atime);	
	printf("stat->mtime:%u \n",stat->mtime);	
	printf("stat->name :%s \n",stat->name);	
	printf("stat->uid  :%s \n",stat->uid);	
	printf("stat->gid :%s \n",stat->gid);	
	printf("stat->n_uid :%u \n",stat->n_uid);	
	printf("stat->n_gid :%u \n",stat->n_gid);	
}
#endif

static int 
virtfs_mode2perm(struct virtfs_session *ses,
                       struct p9_wstat *stat)
{
        int res = 0;
        int mode = stat->mode;

	/* Get the correct perms */
	res = mode & ALLPERMS;

	if ((mode & P9PROTO_DMSETUID) == P9PROTO_DMSETUID)
		res |= S_ISUID;

	if ((mode & P9PROTO_DMSETGID) == P9PROTO_DMSETGID)
		res |= S_ISGID;

	if ((mode & P9PROTO_DMSETVTX) == P9PROTO_DMSETVTX)
		res |= S_ISVTX;
        return res;
}

uint32_t 
convert_to_p9_mode(uint32_t mode)
{
        int res;
        res = mode & 0777;
        if (S_ISDIR(mode))
                res |= P9PROTO_DMDIR;
        if (S_ISSOCK(mode))
		res |= P9PROTO_DMSOCKET;
        if (S_ISFIFO(mode))
		res |= P9PROTO_DMNAMEDPIPE;

	// Is the reason for the red file ?
        if ((mode & S_ISUID) == S_ISUID)
               res |= P9PROTO_DMSETUID;
        if ((mode & S_ISGID) == S_ISGID)
                res |= P9PROTO_DMSETGID;
        if ((mode & S_ISVTX) == S_ISVTX)
                res |= P9PROTO_DMSETVTX;
        return res;
}

static int 
virtfs_mode_to_generic(struct virtfs_session *ses, struct p9_wstat *stat)
{
	uint32_t mode = stat->mode;
	int res;

	res = virtfs_mode2perm(ses, stat);

        if ((mode & P9PROTO_DMDIR) == P9PROTO_DMDIR)
                res |= S_IFDIR;
        else if (mode & P9PROTO_DMSYMLINK)
                res |= S_IFLNK;
        else if (mode & P9PROTO_DMSOCKET)
                res |= S_IFSOCK;
        else if (mode & P9PROTO_DMNAMEDPIPE)
                res |= S_IFIFO;
        else
                res |= S_IFREG;

        return res;
}

/* The u version*/
int
virtfs_stat_vnode_u(struct p9_wstat *stat, struct vnode *vp)
{
	struct virtfs_node *np = VTON(vp);
	struct virtfs_inode *inode = &np->inode;
	struct virtfs_session *ses = np->virtfs_ses;
	int mode;

	//dump_stat(stat);
	inode->i_size = stat->length;
	inode->i_type = stat->type;
	inode->i_dev = stat->dev;
	inode->i_mtime = stat->mtime;
	inode->i_atime = stat->atime;
	inode->i_name = stat->name;
	inode->n_uid = stat->n_uid;
	inode->n_gid = stat->n_gid;
	inode->n_muid = stat->n_muid;
	inode->i_extension = stat->extension;
	inode->i_uid = stat->uid; /* Make sure you copy the numeric */
	inode->i_gid = stat->gid;
	inode->i_muid = stat->muid;
	mode = virtfs_mode_to_generic(ses, stat);
	mode |= (inode->i_mode & ~ALLPERMS);
	inode->i_mode = mode;
	vp->v_type = IFTOVT(inode->i_mode);
	memcpy(&np->vqid, &stat->qid, sizeof(stat->qid));
	//dump_inode(inode);

	return 0;
}

static int
virtfs_setattr(struct vop_setattr_args *ap)
{
	struct vnode *vp = ap->a_vp;
        struct vattr *vap = ap->a_vap;
        struct virtfs_node *node = VTON(vp);
	int error = 0;
        struct p9_wstat wstat;

        memset(&wstat, 0, sizeof(struct p9_wstat));

	/* Set up the wstat structure to write to the disk */
	wstat.mode = convert_to_p9_mode(vap->va_mode);
        wstat.mtime = vap->va_mtime.tv_sec;
        wstat.atime = vap->va_atime.tv_sec;
        wstat.length = vap->va_size;
	// Avoid this for now to avoid the red ?
        wstat.n_uid = vap->va_uid;
       	wstat.n_gid = vap->va_gid;

        error = p9_client_wstat(node->vfid, &wstat);
        if (error < 0)
                return error;

	return 0;
}

static int
virtfs_read(struct vop_read_args *ap)
{
	struct vnode *vp = ap->a_vp;
        struct uio *uio = ap->a_uio;
        struct virtfs_node *np = VTON(vp);
	uint64_t offset;
	uint64_t ret;
	uint64_t resid;
	uint32_t count;
	int error = 0;
	uint64_t filesize;
	struct p9_client *clnt = np->virtfs_ses->clnt;

	if (vp->v_type == VCHR || vp->v_type == VBLK)
                return (EOPNOTSUPP);

	if (vp->v_type != VREG)
		return EISDIR;

        if (uio->uio_resid == 0)
                return (0);
        if (uio->uio_offset < 0)
                return (EINVAL);

	/* Make sure to zeroize the buffer */
	memset(clnt->io_buffer, 0, clnt->msize);

	/* whr in the file are we to start reading */
	offset = uio->uio_offset;
	filesize = np->inode.i_size;
	if(uio->uio_offset >= filesize)
		return 0;

	 p9_debug(VOPS, "virtfs_read called %lu at %lu\n",
            uio->uio_resid, (uintmax_t)uio->uio_offset);

	while ((resid = uio->uio_resid) > 0) {
		if (offset >= filesize)
			break;
		count = MIN(filesize - uio->uio_offset, resid);
		if (count == 0)
			break;

		memset(clnt->io_buffer, 0, clnt->msize);
		/* Copy m_size bytes into the uio */
		ret = p9_client_read(np->vofid, offset, count, clnt->io_buffer);

		/* count can either be what it was here or lesser(based on what we get
		 */
                error = uiomove(clnt->io_buffer, ret, uio);
		if (error)
			return error;

		offset += ret;
        }
	uio->uio_offset = offset;

	return 0;
}

static void
virtfs_itimes(struct vnode *vp)
{
  	struct virtfs_node *node = VTON(vp);
	struct timespec ts;
        struct virtfs_inode *inode = &node->inode;

        vfs_timestamp(&ts);
        inode->i_mtime = ts.tv_sec;
}

static int
virtfs_write(struct vop_write_args *ap)
{
	struct vnode *vp = ap->a_vp;
        struct uio *uio = ap->a_uio;
        struct virtfs_node *node = VTON(vp);
	uint64_t offset;
	uint64_t ret;
	uint64_t resid;
	uint32_t count;
	int error = 0, ioflag, iounit;
	uint64_t file_size;
	struct p9_client *clnt = node->virtfs_ses->clnt;

   	vp = ap->a_vp;
        uio = ap->a_uio;
        ioflag = ap->a_ioflag;
        node = VTON(vp);

        p9_debug(VOPS, "virtfs_write called %#zx at %#jx\n",
            uio->uio_resid, (uintmax_t)uio->uio_offset);

        if (uio->uio_offset < 0)
                return (EINVAL);
        if (uio->uio_resid == 0)
                return (0);

	file_size = node->inode.i_size;

        switch (vp->v_type) {
        case VREG:
                if (ioflag & IO_APPEND)
                        uio->uio_offset = file_size;
                break;
        case VDIR:
                return (EISDIR);
        case VLNK:
                break;
        default:
                panic("%s: bad file type vp: %p", __func__, vp);
        }

        /* If explicitly asked to append, uio_offset can be wrong? */
        if (ioflag & IO_APPEND)
                uio->uio_offset = file_size;

        resid = uio->uio_resid;
	offset = uio->uio_offset;
        error = 0;

	/* Make sure to zeroize the buffer */
	memset(clnt->io_buffer, 0, clnt->msize);

	/* Even though we have a 8k buffer, Qemu is typically doing 8168
	 * because of a HDR of 24. Use that amount for transfers so that we dont
	 * drop anything.
	 */

	iounit = 8168; // msize- 24;

	while ((resid = uio->uio_resid) > 0) {

		memset(clnt->io_buffer, 0, clnt->msize);

		count = MIN(resid, iounit);
		error = uiomove(clnt->io_buffer, count, uio);
		if (error) {
			return error;
		}

		/* Copy m_size bytes from the uio */
		ret = p9_client_write(node->vofid, offset, count, clnt->io_buffer);

		offset += ret;
        }

	/* Update the fields in the node to reflect the change*/
	if (file_size < uio->uio_offset + uio->uio_resid) {
		node->inode.i_size = uio->uio_offset +
			uio->uio_resid;
		vnode_pager_setsize(vp, uio->uio_offset +
			uio->uio_resid);

		/* update the modified timers. */
		virtfs_itimes(vp);
        }

	return 0;
}

static int
virtfs_fsync(struct vop_fsync_args *ap)
{
	return 0;
}

static int
remove_wrapper(struct virtfs_node *node)
{
        int retval = 0;

	retval = p9_client_remove(node->vfid);
	node->vfid = NULL;

	retval = virtfs_cleanup(node);

	return retval;
}

static int
virtfs_remove(struct vop_remove_args *ap)
{
	struct vnode *vp = ap->a_vp;
        struct virtfs_node *node = VTON(vp);
	int ret = 0;

        p9_debug(VOPS, "%s: vp %p node %p \n",
            __func__, vp, node);

        if (vp->v_type == VDIR)
                return (EISDIR);

        ret = remove_wrapper(node);

        return (ret);
}

static int
virtfs_rmdir(struct vop_rmdir_args *ap)
{
	struct vnode *vp = ap->a_vp;
        struct virtfs_node *node = VTON(vp);
	int ret = 0;

        p9_debug(VOPS, "%s: vp %p node %p \n",
            __func__, vp, node);

        ret = remove_wrapper(node);

        return (ret);
}

static int
virtfs_link(struct vop_link_args *ap)
{
	return 0;
}

static int
virtfs_rename(struct vop_rename_args *ap)
{
	return 0;
}
static int
virtfs_symlink(struct vop_symlink_args *ap)
{
	return 0;
}

#if 0
static void 
dump_p9dirent(struct dirent *p)
{
	printf("name :%s d_reclen%hu d_type:%hhu ino_%hu \n",p->d_name,p->d_reclen,p->d_type,p->d_fileno);
}
#endif

/*
 * Minimum length for a directory entry: size of fixed size section of
 * struct dirent plus a 1 byte C string for the name.
 */
static int
virtfs_readdir(struct vop_readdir_args *ap)
{
	struct uio *uio = ap->a_uio;
        struct vnode *vp = ap->a_vp;
        struct dirent cde;
	uint64_t offset = 0,diroffset;
	struct virtfs_node *np = VTON(ap->a_vp);
        int error = 0;
	int count = 0;
	uint64_t file_size;
	struct p9_client *clnt = np->virtfs_ses->clnt;

	if (ap->a_uio->uio_iov->iov_len <= 0)
		return (EINVAL);

	if (vp->v_type != VDIR)
		return (ENOTDIR);

	file_size = np->inode.i_size;

	if (uio->uio_offset >= file_size)
		return ENOENT;

        p9_debug(VOPS, "virtfs_readdir filesize %jd resid %zd\n",
	   (uintmax_t)file_size, uio->uio_resid);

	/* Make sure to zeroize the buffer */
	memset(clnt->io_buffer, 0, clnt->msize);

	count = min(clnt->msize, uio->uio_resid);

	offset = 0;
	/* We havnt reached the end yet. read more. */
        if ((uio->uio_resid >= sizeof(struct dirent))) {
                diroffset = uio->uio_offset;

		/* For now we assume our buffer 8K is enough for entries */
		count = p9_client_readdir(np->vofid, (char *)clnt->io_buffer,
			diroffset, count); /* The max size our client can handle */

		if (count < 0) {
			return (EIO);
		}

		while (offset + QEMU_DIRENTRY_SZ <= count) { // We dont have enough bytes.

			/* Read and make sense out of the buffer in one dirent
			 * This is part of 9p protocol read.
			 * This reads one p9_dirent, now append it to dirent(FREEBSD specifc)
			 * and continuing with the parse
			 */
			memset(&cde, 0, sizeof(struct dirent));
			offset = p9dirent_read(clnt, clnt->io_buffer, offset, count,
				&cde);

			if (offset < 0)
				return EIO;

			cde.d_reclen = GENERIC_DIRSIZ(&cde);
			/*
			 * If there isn't enough space in the uio to return a
			 * whole dirent, break off read
			 */
			if (uio->uio_resid < GENERIC_DIRSIZ(&cde))
				break;

			// Fix this number otherwise it ll break the vfs readir 
			cde.d_fileno = 23+offset;
			//dump_p9dirent(&cde);
			/* Transfer */
			error = uiomove(&cde, GENERIC_DIRSIZ(&cde), uio);

			if (error)
				return error;
			diroffset += cde.d_reclen; // We have added a new direntry.
		}
	}
	/* Pass on last transferred offset */
	uio->uio_offset = diroffset;

	if (ap->a_eofflag) {
		*ap->a_eofflag = 1;
	}

	return (error);
}

static int
virtfs_readlink(struct vop_readlink_args *ap)
{
	return 0;
}

static int
virtfs_inactive(struct vop_inactive_args *ap)
{
	return (0);
}

struct vop_vector virtfs_vnops = {
	.vop_default =		&default_vnodeops,
	.vop_lookup =		vfs_cache_lookup,
	.vop_cachedlookup =	virtfs_lookup,
	.vop_open =		virtfs_open,
	.vop_close =		virtfs_close,
	.vop_access = 		virtfs_access,
	.vop_getattr =		virtfs_getattr,
	.vop_setattr =		virtfs_setattr,
	.vop_reclaim =		virtfs_reclaim,
	.vop_readdir =		virtfs_readdir,
	.vop_create =		virtfs_create,
	.vop_mknod =		virtfs_mknod,
	.vop_read =		virtfs_read,
	.vop_write =		virtfs_write,
	.vop_fsync =		virtfs_fsync,
	.vop_remove =		virtfs_remove,
	.vop_link =		virtfs_link,
	.vop_rename =		virtfs_rename,
	.vop_mkdir =		virtfs_mkdir,
	.vop_rmdir =		virtfs_rmdir,
	.vop_symlink =		virtfs_symlink,
	.vop_readlink =		virtfs_readlink,
	.vop_inactive =		virtfs_inactive,
};
