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

#include "virtfs_proto.h"
#include "virtfs.h"
#include "../client.h"


struct vop_vector virtfs_vnops;
static MALLOC_DEFINE(M_P9NODE, "virtfs_node", "virtfs node structures");

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
	int error = 0;

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
	    		cnp->cn_namelen, &cnp->cn_nameptr, 1);
		if (newfid != NULL) {
			int ltype = 0;

			if (cnp->cn_flags & ISDOTDOT) {
				vhold(dvp);
				ltype = VOP_ISLOCKED(dvp);
				VOP_UNLOCK(dvp, 0);
			}
			/* Vget gets the vp for the newly created vnode. Stick it to the virtfs_node too*/
			error = virtfs_vget_wrapper(mp, NULL, cnp->cn_lkflags, newfid, &vp);

			if (cnp->cn_flags & ISDOTDOT) {
				vn_lock(dvp, ltype | LK_RETRY);
				vdrop(dvp);
			}
		
			if (error)
				return error;

		}
		else {
			/* Not found return NOENTRY.*/
			error = ENOENT;
		}
		if (error == 0) {
			*vpp = vp;
			vref(*vpp);
		}
	}
	/* Store the result the the cache if MAKEENTRY is specified in flags */
	if ((cnp->cn_flags & MAKEENTRY) != 0 && cnp->cn_nameiop != CREATE)
		cache_enter(dvp, *vpp, cnp);	

	return (error);
}

/* We ll implement this once mount works fine .*/
static int
virtfs_create(struct vop_create_args *ap)
{
	p9_debug(VOPS, "create");                      
	return 0;
}

static int
virtfs_mknod(struct vop_mknod_args *ap)
{
	p9_debug(VOPS, "mknod");                      
	
	return 0;
}

static int
virtfs_open(struct vop_open_args *ap)
{
	int error = 0;
	struct virtfs_node *np = VTON(ap->a_vp);
	struct p9_fid *fid = np->vfid;
	struct p9_wstat *stat;
	size_t filesize;

	p9_debug(VOPS, "open \n");                      
	
	if (np->v_opens > 0) {
		np->v_opens++;
		return (0);
	}

	stat  = p9_client_stat(np->vfid);
	if (error != 0)
		return (error);

	if (ap->a_vp->v_type == VDIR) {
		if (np->vofid == NULL) {

			/*ofid is the open fid for this file.*/
			/* Note: Client_walk returns struct p9_fid* */
			np->vofid = p9_client_walk(np->vfid,
			     0, NULL, 1); /* Clone the fid here.*/
			if (np->vofid == NULL) {
				return (-ENOMEM);
			}
		}
		fid = np->vofid;
	}

	filesize = np->inode.i_size;
	/* Use the newly created fid for the open.*/
	error = p9_client_open(fid, ap->a_mode);
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
	p9_debug(VOPS, "close");                      
	

	printf("%s(fid %d ofid %d opens %d)\n", __func__,
	    np->vfid->fid, np->vofid->fid, np->v_opens);
	np->v_opens--;
	if (np->v_opens == 0) {
		//virtfs_relfid(np->virtfs_ses, np->vofid);
		
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

        p9_debug(VOPS,"virtfs_access");

	/* make sure getattr is working correctly and is defined.*/
        error = VOP_GETATTR(vp, &vap, NULL);
        if (error)
                return (error);

        error = check_possible(vp, &vap, accmode);
        if (error)
                return (error);

	/* Call the Generic Access check in VFS*/
        error = vaccess(vp->v_type, vap.va_mode, vap.va_uid, vap.va_gid, accmode,
            cred, NULL);

	return error;
}

static int
virtfs_getattr(struct vop_getattr_args *ap)
{
  	struct vnode *vp = ap->a_vp;
        struct vattr *vap = ap->a_vap;
        struct virtfs_node *node = VTON(vp);
        struct virtfs_inode *inode = &node->inode;
	p9_debug(VOPS, "getattr \n");
	printf("modes in getattr %u %u\n",inode->i_mode,IFTOVT(inode->i_mode));
        
        /* Basic info */
        VATTR_NULL(vap);
        vap->va_atime.tv_sec = inode->i_atime;
        vap->va_mtime.tv_sec = inode->i_mtime;                                           
	vap->va_type =  IFTOVT(inode->i_mode);
        vap->va_mode = inode->i_mode;
        vap->va_uid = inode->n_uid;                                                     
        vap->va_gid = inode->n_gid;                                                     
        vap->va_fsid = vp->v_mount->mnt_stat.f_fsid.val[0];                              
        vap->va_size = inode->i_size;                                                    
        vap->va_filerev = 0;                                             
        vap->va_vaflags = 0;                                               
	printf("type :%u %u\n",vap->va_type,vap->va_mode);
 
	return 0;
}

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

static int 
virtfs_mode2perm(struct virtfs_session *ses,
                       struct p9_wstat *stat)
{
        int res = 0;
        int mode = stat->mode;

	if ((mode & P9PROTO_DMSETUID) == P9PROTO_DMSETUID)
		res |= S_ISUID;

	if ((mode & P9PROTO_DMSETGID) == P9PROTO_DMSETGID)
		res |= S_ISGID;

	if ((mode & P9PROTO_DMSETVTX) == P9PROTO_DMSETVTX)
		res |= S_ISVTX;
        return res;
}

static int 
virtfs_mode_to_generic(struct virtfs_session *ses, struct p9_wstat *stat)
{
	uint32_t mode = stat->mode;
	int res;

	res = virtfs_mode2perm(ses, stat);
	printf("p9_mode_to_unix is not printing ..\n");
        if ((mode & P9PROTO_DMDIR) == P9PROTO_DMDIR)
	{
                res |= S_IFDIR;
		printf("It should be a directory \n");
	}
        else if (mode & P9PROTO_DMSYMLINK)
	{
                res |= S_IFLNK;
		printf("IFLINK \n");
	}
        else if (mode & P9PROTO_DMSOCKET)
	{
                res |= S_IFSOCK;
		printf("SOCK\n");
	}
        else if (mode & P9PROTO_DMNAMEDPIPE)
	{
                res |= S_IFIFO;
		printf("PIPr \n");
	}
        else
	{
                res |= S_IFREG;
		printf(" I thin it hit here ..\n");
	}
	printf("end ..\n");
        return res;
}

/* The u version*/
/* Dont forget to initialize vnode*/
int
virtfs_stat_vnode_u(struct p9_wstat *stat, struct vnode *vp)
{
	struct virtfs_node *np = VTON(vp);
	struct virtfs_inode *inode = &np->inode;
	struct virtfs_session *ses = np->virtfs_ses;

	dump_stat(stat);
	inode->i_size = stat->size;

	inode->i_mtime = stat->mtime;
	inode->i_atime = stat->atime;
	inode->i_name = stat->name;
	inode->i_uid = stat->uid;
	inode->i_gid = stat->gid;
	inode->n_uid = stat->n_uid; /* Make sure you copy the numeric */
	inode->n_gid = stat->n_gid;
	inode->i_mode = virtfs_mode_to_generic(ses, stat);
	memcpy(&np->vqid, &stat->qid, sizeof(stat->qid));
	dump_inode(inode);

	vp->v_type = IFTOVT(inode->i_mode);

	return 0;
}

/* The linux version */
int
virtfs_stat_vnode_l(void)
//struct p9_stat_dotl *stat, struct vnode *vp)
{
	return 0;
}


static int
virtfs_setattr(struct vop_setattr_args *ap)
{
	return 0;
}

static int
virtfs_read(struct vop_read_args *ap)
{
	return 0;
}

static int
virtfs_write(struct vop_write_args *ap)
{
	return 0;
}

static int
virtfs_fsync(struct vop_fsync_args *ap)
{
	return 0;
}

static int
virtfs_remove(struct vop_remove_args *ap)
{
	return 0; 
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
virtfs_mkdir(struct vop_mkdir_args *ap)
{
	return 0;
}

static int
virtfs_rmdir(struct vop_rmdir_args *ap)
{
	return 0;
}

static int
virtfs_symlink(struct vop_symlink_args *ap)
{
	return 0;
}

#if 0
static int
dt_type(struct p9_wstat *stat)
{               
        unsigned long perm = stat->mode;
        int rettype = DT_REG; 
                                          
        if (perm & P9PROTO_DMDIR)
                rettype = DT_DIR;
        if (perm & P9PROTO_DMSYMLINK)
                rettype = DT_LNK;
                        
        return rettype;
}
#endif

static void 
dump_p9dirent(struct dirent *p)
{
	printf("name :%s d_reclen%hu d_type:%hhu\n ",p->d_name,p->d_reclen,p->d_type);
}

/*
 * Minimum length for a directory entry: size of fixed size section of
 * struct dirent plus a 1 byte C string for the name.
 */
static int
virtfs_readdir(struct vop_readdir_args *ap)
{
	struct uio *uio = ap->a_uio;
        struct vnode *vp = ap->a_vp;
	// do we need this ? 
	//struct p9_dirent p9_dirent;
        struct dirent cde;
	uint64_t offset=0;
	struct virtfs_node *np = VTON(ap->a_vp);
        int error = 0;
	int count = 0;
	char *data = NULL;
	int ndirents= 0;
	struct p9_client *clnt = np->virtfs_ses->clnt;
	printf("Readdir called ..\n");

	if (ap->a_uio->uio_iov->iov_len <= 0)
		return (EINVAL);

	if (vp->v_type != VDIR)
		return (ENOTDIR);

	error = 0;

	/* Ok first even before , we go to qemu and fetch for info, do "." and ".."*/
	if (uio->uio_offset == 0) {
		/* . entry */
		cde.d_fileno = np->vfid->fid;
		cde.d_type = DT_DIR;
		cde.d_namlen = 1;
		cde.d_name[0] = '.';
		cde.d_name[1] = '\0';
		cde.d_reclen = GENERIC_DIRSIZ(&cde);
		error = uiomove(&cde, cde.d_reclen, uio);
		if (error)
			return error;

		uio->uio_offset = 1;
		ndirents++;
	}
	if (uio->uio_offset == 1) {
		/* .. entry */
		cde.d_type = DT_DIR;
		cde.d_namlen = 2;
		cde.d_name[0] = '.';
		cde.d_name[1] = '.';
		cde.d_name[2] = '\0';
		cde.d_reclen = GENERIC_DIRSIZ(&cde);
		error = uiomove(&cde, cde.d_reclen, uio);
		if (error)
			return error;

		ndirents++;
	}
	/* Go to QEMU to fetch stuff and make sense out of it. */

	/* Our version of the readdir through the virtio. The data buf has the 
	 * data block information. Now parse through the buf and make the dirent.
	 */

	/* Allocate the  buffer first */
	data = malloc(clnt->msize, M_TEMP, M_WAITOK | M_ZERO);
	if (data == NULL) 
		return EIO;
	count = p9_client_readdir(np->vofid, (char *)data,
		clnt->msize, 0); /* The max size our client can handle */

	if (count < 0) {
		return (EIO);
	}
#if 0
	struct p9_dirent {
        struct p9_qid qid;
        uint64_t d_off;
        unsigned char d_type;
        char d_name[256];
};
#endif // Directory entry
	printf("count number of bytes ..%d\n",count);
	offset = 0;
	// I think p9_dirent is bigger than dirent so we should be ok 
	// We might have some extra rounds of loops.
	// check first if we have enough to get a p9_dirent.
	while (offset < count) {

		/* Read and make sense out of the buffer in one dirent
		 * This is part of 9p protocol read.
		 * This reads one p9_dirent, now append it to dirent(FREEBSD specifc)
		 * and continuing with the parse
		 */
		printf("make sense out of data:%p\n",data);
		memset(&cde, 0, sizeof(struct dirent));
		error = p9dirent_read(clnt, data, count,
                  &cde);
                if (error < 0) {
                      p9_debug(VFS, "returned %d\n", error);
                      return -EIO;
                }
		dump_p9dirent(&cde);

		cde.d_reclen = GENERIC_DIRSIZ(&cde);
		printf("cde entry done \n");
		/*
		 * If there isn't enough space in the uio to return a
		 * whole dirent, break off read
		 */
		if (uio->uio_resid < GENERIC_DIRSIZ(&cde))
			break;

		/* Transfer */
		uiomove(&cde, GENERIC_DIRSIZ(&cde), uio);

		/* Advance */
		offset += cde.d_reclen;
	}

	/* Pass on last transferred offset */
	uio->uio_offset = offset;
	if (data)
		free(data, M_TEMP);

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
