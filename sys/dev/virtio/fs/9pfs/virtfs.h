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

/* This file has prototypes specifc and used all over the FS .*/
#ifndef __VIRTFS__
#define __VIRTFS__

enum v9s_state {
	V9S_INIT,
	V9S_RUNNING,
	V9S_CLOSING,
	V9S_CLOSED,
};

struct virtfs_session;

/* The in memory representation of the on disk inode. Save the current 
 * fields to write it back later. */
/* This is the exact same as stat.*/
struct virtfs_inode {

	/* Make it simple first, Add more fields later */
	uint64_t i_size;
        uint16_t i_type;
        uint32_t i_dev;
        uint32_t i_mode; 
        uint32_t i_atime;
        uint32_t i_mtime;
        uint64_t i_length;
        char *i_name;
        char *i_uid;
        char *i_gid;
        char *i_muid;
        char *i_extension;        /* 9p2000.u extensions */
        uid_t n_uid;            /* 9p2000.u extensions */
        gid_t n_gid;            /* 9p2000.u extensions */
        uid_t n_muid;           /* 9p2000.u extensions */
};               

/* A Plan9 node. */
struct virtfs_node {
	struct p9_fid *vfid; /*node fid*/
	struct p9_fid *vofid; /* open fid for this file */
	uint32_t v_opens; /* Number of open handlers. */
	struct virtfs_qid vqid; /* the server qid, will be from the host*/
	struct vnode *v_node; /* vnode for this fs_node. */
	struct virtfs_inode inode; /* This represents the ondisk in mem inode */
	struct virtfs_session *virtfs_ses; /*  Session_ptr for this node */
};

#define VTON(vp) vp->v_data
#define NTOV(node) node->v_node

#define	VFSTOP9(mp) ((mp)->mnt_data)
#define QEMU_DIRENTRY_SZ 25

#define	MAXUNAMELEN	32

/* Session structure for the FS */
struct virtfs_session {

     unsigned char flags; /* these flags for the session */
     struct mount *virtfs_mount; /* mount point */
     struct virtfs_node rnp; /* root virtfss_node for this session */
     uid_t uid;     /* the uid that has access */
     struct p9_client *clnt; /* 9p client */
     struct mtx virtfs_lock;
};

struct virtfs_mount {
	int virt_debug;
	struct virtfs_session virtfs_session;
	struct mount *virtfs_mountp;
};

/* All session flags based on 9p versions  */
enum virt_session_flags {
	VIRTFS_PROTO_2000U	= 0x01,
	VIRTFS_PROTO_2000L	= 0x02,
};

/* These are all the VIRTFS specific vops */
int virtfs_stat_vnode_l(void);
int virtfs_stat_vnode_u(struct p9_wstat *st, struct vnode *vp);
int virtfs_reload_stats(struct vnode *vp);
int virtfs_proto_dotl(struct virtfs_session *virtfss);
struct p9_fid *virtfs_init_session(struct mount *mp);
void virtfs_close_session(struct mount *mp);
int virtfs_vget(struct mount *mp, ino_t ino, int flags, struct vnode **vpp);
int virtfs_vget_wrapper(struct mount *mp, struct virtfs_node *np, int flags,
	struct p9_fid *fid, struct vnode **vpp);
void dispose_node(struct virtfs_node **node);

#endif /* __VIRTFS__ */
