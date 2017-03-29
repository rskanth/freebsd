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
#include <sys/priv.h>

#include <sys/types.h>
#include <fcntl.h>
#include "virtfs_proto.h"
#include "virtfs.h"
#include "../client.h"


#include <vm/vm.h>
#include <vm/vm_extern.h>
#include <vm/vm_object.h>
#include <vm/vnode_pager.h>
#include <sys/buf.h>
#include <sys/bio.h>
/* File permissions. */
#define IEXEC           0000100 /* Executable. */
#define IWRITE          0000200 /* Writeable. */
#define IREAD           0000400 /* Readable. */
#define ISVTX           0001000 /* Sticky bit. */
#define ISGID           0002000 /* Set-gid. */
#define ISUID           0004000 /* Set-uid. */

struct vop_vector virtfs_vnops;
uint32_t convert_to_p9_mode(uint32_t mode);

static void
virtfs_itimes(struct vnode *vp)
{
  	struct virtfs_node *node = VTON(vp);
	struct timespec ts;
        struct virtfs_inode *inode = &node->inode;

        vfs_timestamp(&ts);
        inode->i_mtime = ts.tv_sec;
}

int
virtfs_cleanup(struct virtfs_node *node)
{
	struct vnode *vp = NTOV(node);
	struct virtfs_session *ses = node->virtfs_ses;
	/* Invalidate all entries to a particular vnode. */
        cache_purge(vp);

        /* Destroy the vm object and flush associated pages. */
        vnode_destroy_vobject(vp);
	vfs_hash_remove(vp);

	/* Remove the virtfs_node from the list before we cleanup.*/
	VIRTFS_LOCK(ses);
	STAILQ_REMOVE(&ses->virt_node_list, node, virtfs_node, virtfs_node_next);
	VIRTFS_UNLOCK(ses);

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
	if (virtfs_node == NULL)
            return 0;

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

	/* If its not hardlink only then do the walk, else we are done. */
	if (!(perm & P9PROTO_DMLINK)) {
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
	}
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
        uint32_t mode = MAKEIMODE(ap->a_vap->va_type, ap->a_vap->va_mode);
        struct virtfs_node *dir_node = VTON(dvp);
	struct virtfs_inode *inode = &dir_node->inode;
	uint32_t perm;
        int ret = 0;

        p9_debug(VOPS, "%s: dvp %p\n", __func__, dvp);

        perm = convert_to_p9_mode(mode);

        ret = create_wrapper(dir_node, cnp, NULL, perm, P9PROTO_ORDWR, vpp);
	if (ret == 0) {
		INCR_LINKS(inode);
	}

	return ret;
}

static int
virtfs_mkdir(struct vop_mkdir_args *ap)
{
	struct vnode *dvp = ap->a_dvp;
        struct vnode **vpp = ap->a_vpp;
        struct componentname *cnp = ap->a_cnp;
        uint32_t mode = MAKEIMODE(ap->a_vap->va_type, ap->a_vap->va_mode);
        struct virtfs_node *dir_node = VTON(dvp);
	struct virtfs_inode *inode = &dir_node->inode;
	uint32_t perm;
        int ret = 0;

        p9_debug(VOPS, "%s: dvp %p\n", __func__, dvp);

        perm = convert_to_p9_mode(mode | S_IFDIR);

        ret = create_wrapper(dir_node, cnp, NULL, perm, P9PROTO_ORDWR, vpp);
	if (ret == 0)
		INCR_LINKS(inode);
	return ret;
}

static int
virtfs_mknod(struct vop_mknod_args *ap)
{
	struct vnode *dvp = ap->a_dvp;
        struct vnode **vpp = ap->a_vpp;
        struct componentname *cnp = ap->a_cnp;
        uint32_t mode = MAKEIMODE(ap->a_vap->va_type, ap->a_vap->va_mode);
        struct virtfs_node *dir_node = VTON(dvp);
	struct virtfs_inode *inode = &dir_node->inode;
	uint32_t perm;
        int ret = 0;

        p9_debug(VOPS, "%s: dvp %p\n", __func__, dvp);

        perm = convert_to_p9_mode(mode);

        ret = create_wrapper(dir_node, cnp, NULL, perm, P9PROTO_OREAD, vpp);

	if (ret == 0) {
		INCR_LINKS(inode);
	}

	return ret;
}

static int virtfs_uflags_mode(int uflags, int extended)
{
        uint32_t ret;

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
	uint32_t mode;

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
	vap->va_nlink = inode->i_links_count;
	vap->va_blocksize = PAGE_SIZE;
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
        uint32_t res = 0;
        uint32_t mode = stat->mode;

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
        uint32_t res = 0;
        res = mode & ALLPERMS;
        if (S_ISDIR(mode))
                res |= P9PROTO_DMDIR;
        if (S_ISSOCK(mode))
  		res |= P9PROTO_DMDIR; // hack the socket for bonnie.
        if (S_ISFIFO(mode))
		res |= P9PROTO_DMNAMEDPIPE;

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
	uint32_t res;

	res = virtfs_mode2perm(ses, stat);

        if ((mode & P9PROTO_DMDIR) == P9PROTO_DMDIR)
                res |= S_IFDIR;
        else if (mode & P9PROTO_DMSYMLINK)
                res |= S_IFLNK;
        else if (mode & P9PROTO_DMSOCKET)
                res |= S_IFDIR; // h ack it for bonnie./
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
	uint32_t mode;

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
	inode->i_uid = stat->uid;
	inode->i_gid = stat->gid;
	inode->i_muid = stat->muid;
	SET_LINKS(inode);
	mode = virtfs_mode_to_generic(ses, stat);
	mode |= (inode->i_mode & ~ALLPERMS);
	inode->i_mode = mode;
	vp->v_type = IFTOVT(inode->i_mode);
	memcpy(&np->vqid, &stat->qid, sizeof(stat->qid));
	//dump_inode(inode);

	return 0;
}

static int
virtfs_inode_to_wstat(struct virtfs_inode *inode , struct p9_wstat *wstat)
{
	//dump_stat(stat);
	wstat->length = inode->i_size;
	wstat->type = inode->i_type;
        wstat->dev = inode->i_dev;
	wstat->mtime = inode->i_mtime;
	wstat->atime = inode->i_atime;
	wstat->name = inode->i_name;
	wstat->n_uid = inode->n_uid;
	wstat->n_gid = inode->n_gid;
	wstat->n_muid = inode->n_muid;
	wstat->extension = inode->i_extension;
	wstat->uid = inode->i_uid;
	wstat->gid = inode->i_gid;
	wstat->muid = inode->i_muid;
	wstat->mode = convert_to_p9_mode(inode->i_mode);

	return 0;
}

static int
virtfs_chown(struct vnode *vp, uid_t uid, gid_t gid, struct ucred *cred,
    struct thread *td)
{
        struct virtfs_node *node = VTON(vp);
        struct virtfs_inode *inode = &node->inode;
        uid_t ouid;
        gid_t ogid;
        int error = 0;

        if (uid == (uid_t)VNOVAL)
                uid = inode->n_uid;
        if (gid == (gid_t)VNOVAL)
                gid = inode->n_gid;
        /*
         * To modify the ownership of a file, must possess VADMIN for that
         * file.
         */
        if ((error = VOP_ACCESSX(vp, VWRITE_OWNER, cred, td)))
                return (error);
        /*
         * To change the owner of a file, or change the group of a file to a
         * group of which we are not a member, the caller must have
         * privilege.
         */
        if (((uid != inode->n_uid && uid != cred->cr_uid) ||
            (gid != inode->n_gid && !groupmember(gid, cred))) &&
            (error = priv_check_cred(cred, PRIV_VFS_CHOWN, 0)))
                return (error);
        ogid = inode->n_gid;
        ouid = inode->n_uid;

        inode->n_gid = gid;
        inode->n_uid = uid;

        if ((inode->i_mode & (ISUID | ISGID)) &&
            (ouid != uid || ogid != gid)) {
                if (priv_check_cred(cred, PRIV_VFS_RETAINSUGID, 0))
                        inode->i_mode &= ~(ISUID | ISGID);
        }
        p9_debug(VOPS, "%s: vp %p, cred %p, td %p - ret OK\n", __func__, vp,
            cred, td);
        return (0);
}

static int
virtfs_chmod(struct vnode *vp, uint32_t  mode, struct ucred *cred, struct thread *td)
{
        struct virtfs_node *node = VTON(vp);
        struct virtfs_inode *inode = &node->inode;
        uint32_t nmode;
        int error = 0;

        p9_debug(VOPS, "%s: vp %p, mode %x, cred %p, td %p\n", __func__, vp,
            mode, cred, td);
        /*
         * To modify the permissions on a file, must possess VADMIN
         * for that file.
         */
        if ((error = VOP_ACCESS(vp, VADMIN, cred, td)))
                return (error);

        /*
         * Privileged processes may set the sticky bit on non-directories,
         * as well as set the setgid bit on a file with a group that the
         * process is not a member of. Both of these are allowed in
         * jail(8).
         */
        if (vp->v_type != VDIR && (mode & S_ISTXT)) {
                if (priv_check_cred(cred, PRIV_VFS_STICKYFILE, 0))
                        return (EFTYPE);
        }
        if (!groupmember(inode->n_gid, cred) && (mode & ISGID)) {
                error = priv_check_cred(cred, PRIV_VFS_SETGID, 0);
                if (error)
                        return (error);
        }

        /*
         * Deny setting setuid if we are not the file owner.
         */
        if ((mode & ISUID) && inode->n_uid != cred->cr_uid) {
                error = priv_check_cred(cred, PRIV_VFS_ADMIN, 0);
                if (error)
                        return (error);
        }
        nmode = inode->i_mode;
        nmode &= ~ALLPERMS;
        nmode |= (mode & ALLPERMS);
        inode->i_mode = nmode;

        p9_debug(VOPS, "%s: to mode %x\n", __func__, nmode);

        return (error);
}

/*
static int dump_vap(struct vattr *vp)
{
        printf("vap->va_type %d:
                vap->va_fsid
                vap->va_nlink
                vap->va_fileid
                vap->vap->va_bytes
                \n");
}*/

static int
virtfs_setattr(struct vop_setattr_args *ap)
{
	struct vnode *vp = ap->a_vp;
        struct vattr *vap = ap->a_vap;
        struct virtfs_node *node = VTON(vp);
	struct virtfs_inode *inode = &node->inode;
	struct ucred *cred = ap->a_cred;
	struct thread *td = curthread;
	int error = 0;
        struct p9_wstat wstat;

        memset(&wstat, 0, sizeof(struct p9_wstat));

  //      dump_vap(vap);

	if ((vap->va_type != VNON) || (vap->va_nlink != VNOVAL) ||
	    (vap->va_fsid != VNOVAL) || (vap->va_fileid != VNOVAL) ||
	    (vap->va_blocksize != VNOVAL) || (vap->va_rdev != VNOVAL) ||
	    (vap->va_bytes != VNOVAL) || (vap->va_gen != VNOVAL)) {
		p9_debug(VOPS, "%s: unsettable attribute\n", __func__);
		return (EINVAL);
	}
        /* Check if we need to change the ownership of the file*/

	if (vap->va_uid != (uid_t)VNOVAL || vap->va_gid != (gid_t)VNOVAL) {
		if (vp->v_mount->mnt_flag & MNT_RDONLY)
			return (EROFS);
		p9_debug(VOPS, "%s: vp:%p td:%p uid/gid %x/%x\n", __func__,
		    vp, td, vap->va_uid, vap->va_gid);
		error = virtfs_chown(vp, vap->va_uid, vap->va_gid, cred, td);
		if (error)
			return (error);
	}

        /* Check for mode changes */
	if (vap->va_mode != (mode_t)VNOVAL) {
		if (vp->v_mount->mnt_flag & MNT_RDONLY)
			return (EROFS);
		p9_debug(VOPS, "%s: vp:%p td:%p mode %x\n", __func__, vp, td,
		    vap->va_mode);

		error = virtfs_chmod(vp, (int)vap->va_mode, cred, td);
		if (error)
			return (error);
	}

	if (vap->va_atime.tv_sec != VNOVAL ||
	    vap->va_mtime.tv_sec != VNOVAL ||
	    vap->va_birthtime.tv_sec != VNOVAL) {
		p9_debug(VOPS, "%s: vp:%p td:%p time a/m/b %jx/%jx/%jx\n",
		    __func__, vp, td, (uintmax_t)vap->va_atime.tv_sec,
		    (uintmax_t)vap->va_mtime.tv_sec,
		    (uintmax_t)vap->va_birthtime.tv_sec);

		virtfs_itimes(vp);
		return (0);
	}
	/* Write the inode structure values into wstat */
	virtfs_inode_to_wstat(inode, &wstat);
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
		count = min(filesize - uio->uio_offset, resid);
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
	struct vop_open_args map;

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

	/* Before we do that actual write, make sure the vp is open. Only in case of ktr_drain/write, it
	 * could call on a closed file. Force open for now.
	 */

	if (node->vofid == NULL) {
		// Force a file open
		map.a_mode = 3;//
		map.a_td = curthread;
		map.a_vp = vp;
		virtfs_open(&map);
	}

	while ((resid = uio->uio_resid) > 0) {

		memset(clnt->io_buffer, 0, clnt->msize);

		count = MIN(resid, iounit);
		error = uiomove(clnt->io_buffer, count, uio);
		if (error) {
			return error;
		}

		/* Copy m_size bytes from the uio */
		ret = p9_client_write(node->vofid, offset, count, clnt->io_buffer);
	        p9_debug(VOPS, "virtfs_write called %#zx at %#jx\n",
            		uio->uio_resid, (uintmax_t)uio->uio_offset);

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
	struct virtfs_inode *inode = &node->inode;
	struct vnode *dvp = ap->a_dvp;
        struct virtfs_node *dir_node = VTON(dvp);
	struct virtfs_inode *dir_ino = &dir_node->inode;

	int ret = 0;

        p9_debug(VOPS, "%s: vp %p node %p \n",
            __func__, vp, node);

        if (vp->v_type == VDIR)
                return (EISDIR);

        ret = remove_wrapper(node);

	if (ret == 0) {
		CLR_LINKS(inode);
		DECR_LINKS(dir_ino);
	}

        return (ret);
}

static int
virtfs_rmdir(struct vop_rmdir_args *ap)
{
	struct vnode *vp = ap->a_vp;
        struct virtfs_node *node = VTON(vp);
	struct virtfs_inode *inode = &node->inode;
        struct vnode *dvp = ap->a_dvp;
        struct virtfs_node *dir_node = VTON(dvp);
        struct virtfs_inode *dir_ino = &dir_node->inode;
	int ret = 0;

        p9_debug(VOPS, "%s: vp %p node %p \n",
            __func__, vp, node);

        ret = remove_wrapper(node);
	if (ret == 0) {
		CLR_LINKS(inode);
		DECR_LINKS(dir_ino);
	}

        return (ret);
}

/* Hard link */
#if 0
static int
virtfs_link(struct vop_link_args *ap)
{
	struct vnode *tdvp = ap->a_tdvp;
        struct vnode *vp = ap->a_vp;
        struct componentname *cnp = ap->a_cnp;
        int ret = 0;

        p9_debug(vops, "%s: tdvp %p\n", __func__, tdvp);

        ret = create_wrapper(dir_node, cnp, NULL, P9PROTO_DMLINK, P9PROTO_OREAD, &vp);

	      int retval;
        struct p9_fid *oldfid;

        p9_debug(P9_DEBUG_VFS, " %lu,%pd,%pd\n",
                 dir->i_ino, dentry, old_dentry);

        oldfid = p9_client_walk(old_dentry);
        if (IS_ERR(oldfid))
                return PTR_ERR(oldfid);

        sprintf(name, "%d\n", oldfid->fid);
        retval = v9fs_vfs_mkspecial(dir, dentry, P9_DMLINK, name);
        if (!retval) {
                v9fs_refresh_inode(oldfid, d_inode(old_dentry));
                v9fs_invalidate_inode_attr(dir);
        }
        p9_client_clunk(oldfid);
        return retval;


	return ret;
}

/* Similar to removing a file reference */
static int
virtfs_unlink(struct vop_unlink_args *ap)
{
	struct vnode *vp = ap->a_vp;
        struct virtfs_node *node = VTON(vp);
	struct virtfs_inode *inode = &node->inode;
	struct vnode *dvp = ap->a_dvp;
        struct virtfs_node *dir_node = VTON(dvp);
	struct virtfs_inode *dir_ino = &dir_node->inode;

	int ret = 0;

        p9_debug(VOPS, "%s: vp %p node %p \n",
            __func__, vp, node);

        if (vp->v_type == VDIR)
                return (EISDIR);

        ret = remove_wrapper(node);

	if (ret == 0) {
		CLR_LINKS(inode);
		DECR_LINKS(dir_ino);
	}

        return (ret);
}

#endif

static int
virtfs_rename(struct vop_rename_args *ap)
{
	return 0;
}

/* Soft links */
static int
virtfs_symlink(struct vop_symlink_args *ap)
{
	struct vnode *dvp = ap->a_dvp;
        struct vnode **vpp = ap->a_vpp;
        struct componentname *cnp = ap->a_cnp;
        uint32_t mode = MAKEIMODE(ap->a_vap->va_type, ap->a_vap->va_mode);
        struct virtfs_node *dir_node = VTON(dvp);
	struct virtfs_inode *inode = &dir_node->inode;
	uint32_t perm;
        int ret = 0;

        p9_debug(VOPS, "%s: dvp %p\n", __func__, dvp);

        perm = convert_to_p9_mode(mode);

        ret = create_wrapper(dir_node, cnp, NULL, P9PROTO_DMSYMLINK | perm, P9PROTO_OREAD, vpp);

	if (ret == 0) {
		INCR_LINKS(inode);
	}

	return ret;
}

/*static void
dump_p9dirent(struct dirent *p)
{
	printf("name :%s d_reclen%hu d_type:%hhu ino_%hu \n",p->d_name,p->d_reclen,p->d_type,p->d_fileno);
}
*/

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
	uint64_t offset = 0, diroffset = 0;
	struct virtfs_node *np = VTON(ap->a_vp);
        int error = 0;
	uint32_t count = 0;
	uint64_t file_size;
	uint64_t resid;
	struct p9_client *clnt = np->virtfs_ses->clnt;
	struct p9_dirent dent;

	if (ap->a_uio->uio_iov->iov_len <= 0)
		return EINVAL;

	if (vp->v_type != VDIR)
		return ENOTDIR;

	file_size = np->inode.i_size;

	if (uio->uio_offset >= file_size)
	{
		printf("file_size enoent ..\n");
		return ENOENT;
	}

        p9_debug(VOPS, "virtfs_readdir filesize %jd resid %zd\n",
	   (uintmax_t)file_size, uio->uio_resid);

	memset(clnt->io_buffer, 0, clnt->msize);
	memset(&dent, 0, sizeof(dent));
	/* We havnt reached the end yet. read more. */
        if ((uio->uio_resid >= sizeof(struct dirent))) {

                diroffset = uio->uio_offset;

		while (diroffset < file_size && (resid = uio->uio_resid) > 0) {

			printf("diroffset %llu count%u file_size %llu\n",diroffset,count,file_size);
			/* Make sure to zeroize the buffer */
		   	if (diroffset >= file_size)
				break;
			count = min(file_size - uio->uio_offset, resid);
			if (count == 0)
				break;

			printf(" why is count :%u\n",count);
			/* For now we assume our buffer 8K is enough for entries */
			count = p9_client_readdir(np->vofid, (char *)clnt->io_buffer,
				diroffset, count); /* The max size our client can handle */

			printf("count%u\n",count);
			if( count == 0) break;

			if (count < 0) {
				return EIO;
			}

			offset = 0;

			// Parse through the buffer to make the direntries.
			while (offset + QEMU_DIRENTRY_SZ <= count) {

				/* Read and make sense out of the buffer in one dirent
				 * This is part of 9p protocol read.
				 * This reads one p9_dirent, now append it to dirent(FREEBSD specifc)
				 * and continuing with the parse
				 */
				memset(&cde, 0, sizeof(struct dirent));
				offset = p9_dirent_read(clnt, clnt->io_buffer, offset, count,
					&dent);

				if (offset < 0 || offset > count) // We are beyond count ?
					return EIO;

				// Copy back the dent into the cde.
				strncpy(cde.d_name , dent.d_name, dent.len);
                                memcpy(&cde.d_fileno, &dent.qid, sizeof(ino_t));
                                cde.d_type = dent.d_type;
				cde.d_namlen = dent.len;

				cde.d_reclen = GENERIC_DIRSIZ(&cde);

				printf("offset in the buffer:%d  %d \n",offset,cde.d_reclen);
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
				printf("rec len :%d  %lu \n",cde.d_reclen,uio->uio_offset);
				diroffset = dent.d_off; // We have added a new direntry.
			}
		 }
	} /// this is for the if conditions
	/* Pass on last transferred offset */
	uio->uio_offset = diroffset;

	 if (ap->a_eofflag)
                *ap->a_eofflag = (uio->uio_offset >= file_size);

	return (error);
}

/* this needs some fixing ..*/
static int
virtfs_strategy
        (struct vop_strategy_args /* {
                struct buf *a_vp;
                struct buf *a_bp;
        } */ *ap)
{
	struct vnode *vp = ap->a_vp;
        struct buf *bp = ap->a_bp;
        struct virtfs_node *node = VTON(vp);

	if (bp->b_iocmd == BIO_READ) {

		p9_client_read(node->vofid, 0, PAGE_SIZE, (char *)bp);
                return (0);
        }

	p9_client_write(node->vofid, 0, PAGE_SIZE, (char *)bp);

	return 0;
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
//	.vop_link =		virtfs_link,
//	.vop_unlink = 		virtfs_unlink,
	.vop_rename =		virtfs_rename,
	.vop_mkdir =		virtfs_mkdir,
	.vop_rmdir =		virtfs_rmdir,
	.vop_symlink =		virtfs_symlink,
	.vop_strategy = 	virtfs_strategy,
};
