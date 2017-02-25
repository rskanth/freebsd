#ifndef NET_9P_CLIENT_H
#define NET_9P_CLIENT_H


#include <sys/param.h>
#include <sys/errno.h>
#include <sys/types.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/condvar.h>
#include <sys/queue.h>
#include <sys/systm.h>
#include <sys/mount.h>
#include <sys/param.h>
#include <sys/malloc.h>
#include <sys/kernel.h>
#include <sys/proc.h>
#include <sys/dirent.h>
#include <machine/stdarg.h>

#include "9p.h"
enum p9_proto_versions{
	p9_proto_legacy,
	p9_proto_2000u,
	p9_proto_2000L,
};

/* Dunno if this is needeed ? */
enum p9_req_status_t {
	REQ_STATUS_IDLE,
	REQ_STATUS_ALLOC,
	REQ_STATUS_UNSENT,
	REQ_STATUS_SENT,
	REQ_STATUS_RCVD,
	REQ_STATUS_FLSHD,
	REQ_STATUS_ERROR,
};

struct p9_req_t {
	struct p9_buffer *tc;
	struct p9_buffer *rc;
};

#define MAX_ERRNO 30
struct p9_client {
	struct mtx p9clnt_mtx;
	struct mtx p9req_mtx;
	struct cv req_cv;
	unsigned int msize;
	char *io_buffer;
#define MTU 8192
	unsigned char proto_version;
	struct p9_trans_module *trans_mod;
	void *trans;
	struct unrhdr *fidpool;
	char name[32];
};

/* The main fid structure which keeps track of the file.*/
struct p9_fid {
	struct p9_client *clnt;
	uint32_t fid;
	int mode;        // Open file mode.
	struct p9_qid qid;
	uint32_t iounit;
	uid_t uid;      // this is the uid for this fid.
};

/* Session and client Init Ops */

struct p9_client *p9_client_create(struct mount *mp);
void p9_client_destroy(struct p9_client *clnt);
struct p9_fid *p9_client_attach(struct p9_client *clnt);

/* FILE OPS - These are individually called from the specific vop function */

int p9_client_open(struct p9_fid *fid, int mode);
int p9_client_close(struct p9_fid *fid);
struct p9_fid *p9_client_walk(struct p9_fid *oldfid, uint16_t nwname,
		char **wnames, int clone);
struct p9_fid *p9_fid_create(struct p9_client *clnt);
void p9_fid_destroy(struct p9_fid *fid);
int p9_client_clunk(struct p9_fid *fid);

int p9_client_version(struct p9_client *clnt);
int p9_client_readdir(struct p9_fid *fid, char *data, uint64_t offset, uint32_t count);
int p9_client_read(struct p9_fid *fid, uint64_t offset, uint32_t count, char *data);
int p9_client_write(struct p9_fid *fid, uint64_t offset, uint32_t count, char *data);
int p9_client_file_create(struct p9_fid *fid, char *name, uint32_t perm, int mode,
                     char *extension);
int p9_client_remove(struct p9_fid *fid);

int p9_dirent_read(struct p9_client *clnt, char *buf, int start, int len,
		  struct dirent *dirent);
struct p9_wstat *p9_client_stat(struct p9_fid *fid);
int p9_client_wstat(struct p9_fid *fid, struct p9_wstat *wst);
int p9_client_setattr(struct p9_fid *fid, struct p9_iattr_dotl *attr);
int p9_client_statfs(struct p9_fid *fid, struct p9_statfs *stat);

struct p9_stat_dotl *p9_client_getattr(struct p9_fid *fid, uint64_t request_mask);
//struct p9_stat_dotl *p9_client_getattr_dotl(struct p9_fid *fid, uint64_t request_mask);
int p9_client_statread(struct p9_client *clnt, char *data, size_t len, struct p9_wstat *st);
int p9_is_proto_dotu(struct p9_client *clnt);
int p9_is_proto_dotl(struct p9_client *clnt);
void p9_client_cb(struct p9_client *c, struct p9_req_t *req);
int p9stat_read(struct p9_client *clnt, char *data, size_t len, struct p9_wstat *st); 

extern int p9_debug_level; /* All debugs on now */

#define P9_DEBUG_TRANS            0x0001
#define P9_DEBUG_SUBR             0x0002
#define P9_DEBUG_VFS              0x0004
#define P9_DEBUG_PROTO            0x0008
#define P9_DEBUG_VOPS             0x0010
#define P9_DEBUG_COMPONENTNAME    0x0020
#define P9_DEBUG_VNODE            0x0040
#define P9_DEBUG_DIR              0x0080
#define P9_DEBUG_NAMECACHE        0x0100
#define P9_DEBUG_NODE             0x0200

#define p9_debug(category, fmt, ...) \
	do {                             \
		if ((p9_debug_level & P9_DEBUG_##category) != 0)  \
	                 printf(fmt, ##__VA_ARGS__);  \
	 } while (0)

#endif /* NET_9P_CLIENT_H */
