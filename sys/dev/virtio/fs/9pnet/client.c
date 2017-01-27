/*

 * net/9p/clnt.c
 *
 * 9P Client API -  We are going to built this a module.
 */


// ALl local headers move to include and then compile with the include.
#include "../client.h"
#include "transport.h"
#include "../protocol.h"
#include "../9p.h"

int p9_debug_level = 0xFFFF;

struct p9_req_t *p9_get_request(void);
void p9_client_begin_disconnect(struct p9_client *clnt);
void p9_client_disconnect(struct p9_client *clnt);
#define P9CLNT_MTX(_sc) &(_sc)->p9clnt_mtx
#define P9REQ_MTX(_sc) &(_sc)->p9req_mtx
#define P9CLNT_LOCK(_sc) mtx_lock(P9CLNT_MTX(_sc))
#define P9CLNT_UNLOCK(_sc) mtx_unlock(P9CLNT_MTX(_sc))
#define P9CLNT_INIT(_sc) mtx_init(P9CLNT_MTX(_sc), "clnt-spin", NULL, MTX_SPIN);
#define P9REQ_INIT(_sc) mtx_init(P9REQ_MTX(_sc), "Req- mutex lock", NULL, MTX_DEF);
#define P9REQMTX_LOCK(_sc) mtx_lock(P9REQ_MTX(_sc))
#define P9REQMTX_UNLOCK(_sc) mtx_unlock(P9REQ_MTX(_sc))

inline int p9_is_proto_dotl(struct p9_client *clnt)
{
	return clnt->proto_version == p9_proto_2000L;
}

inline int p9_is_proto_dotu(struct p9_client *clnt)
{
	return clnt->proto_version == p9_proto_2000u;
}

static int 
p9_parse_opts(struct mount  *mp, struct p9_client *clnt)
{
	char *trans;
	int error = 0;

	clnt->proto_version = p9_proto_2000u; /* Lets just do this for now*/
	clnt->msize = 8192;

    	trans = vfs_getopts(mp->mnt_optnew, "trans", &error);
    	if (error)
        	return (error);

	/* This will be moved to mod where we can have multiple entries in the 
	 * table to search for and return the correct pointer. For now its a 
	 * global pointer only for the trans_virtio set */
    	clnt->trans_mod = p9_get_trans_by_name(trans);
    	if (clnt->trans_mod == NULL) {
            	printf("Could not find request transport: %s\n",trans);
            	error = -EINVAL;
        }
	return error;
}

static struct p9_buffer *p9_buffer_alloc(int alloc_msize)
{
	struct p9_buffer *fc;

	fc = malloc(sizeof(struct p9_buffer) + alloc_msize, M_TEMP, M_WAITOK | M_ZERO);
	if (!fc)
		return NULL;
	fc->capacity = alloc_msize;
	fc->offset = 0;
	fc->size = 0;
	fc->sdata = (char *) fc + sizeof(struct p9_buffer);

	return fc;
}

static void
p9_buffer_free(struct p9_buffer *buf)
{
	/* Free the sdata buffers first then the whole strucutre*/
	free(buf, M_TEMP);
}

static void p9_free_req(struct p9_req_t *r)
{
	/* Creates its own pool later. */
	if (r->tc)
		p9_buffer_free(r->tc);
	if (r->rc)
		p9_buffer_free(r->rc);

	free(r, M_TEMP);
}

static struct p9_req_t *
p9_client_request(struct p9_client *c, int8_t type, const char *fmt, ...);

/* This will be called for every request
 * We will do pool and stuff later.*/
struct p9_req_t *p9_get_request(void)
{
	struct p9_req_t *req;
	int alloc_msize = 8192;

	req = malloc(sizeof(*req), M_TEMP, M_WAITOK | M_ZERO);
	if (req == NULL) return NULL;
	if (!req->tc)
		req->tc = p9_buffer_alloc(alloc_msize);
	if (!req->rc) {
		req->rc = p9_buffer_alloc(alloc_msize);
		printf("receive buffer %p \n",req->rc);	
	}	

	if (req->tc == NULL || req->rc == NULL) 
		return NULL;
	return req;
}

static void
dump_pdu(struct p9_buffer *buf)
{
	/* Char buffer */
	int i;
	char *tbuf = &buf->sdata[0];
	/* Just dump 30 character of the pdu */

	printf("buf->sdata[0] address %p \n",&tbuf[0]);
	/*Dump all the first 30 characters */
	for(i=0;i<30;i++)
		printf("%hhu ",tbuf[i]);
}

static int
p9_parse_receive(struct p9_buffer *buf)
{
	int8_t type;
        int16_t tag;
        int32_t size;
        int err;

        buf->offset = 0;

	/* This value is set by QEMU for the header.*/
        if (buf->size == 0) buf->size = 7;

	dump_pdu(buf);

	/* This is the initial header parse. size, type, and tag .*/
        err = p9pdu_readf(buf, 0, "dbw", &size, &type, &tag);
        if (err)
                goto exit;

        buf->size = size;
        buf->id = type;
        buf->tag = tag;

        p9_debug(TRANS, "<<< size=%d type: %d tag: %d\n",
                 buf->size, buf->id, buf->tag);
exit:
        return err;
}

static int
p9_client_check_return(struct p9_client *c,
		       struct p9_req_t *req)
{

        int err;
        int ecode;

	dump_pdu(req->tc);
	/* Check what we have in the receive bufer .*/
        err = p9_parse_receive(req->rc);

        if (err) {
                p9_debug(TRANS, "couldn't parse receive buffer %d\n", err);
                return err;
        }
	/* No error , We are done with the preprocessing. Return to the caller
	 * and process the actual data.
	 */ 
        if (req->rc->id != P9PROTO_RERROR)
                return 0;

	/* TODO: This supports only unix version 9p which is good for now*/
	/* Find out the actual error .*/
        err = p9pdu_readf(req->rc, c->proto_version, "d", &ecode);
        err = -ecode;

        p9_debug(TRANS, "<<< RLERROR (%d)\n", -ecode);

        return err;
}

static struct p9_req_t *p9_client_prepare_req(struct p9_client *c,
					      int8_t type, int req_size,
					      const char *fmt, __va_list ap)
{
	int err;
	struct p9_req_t *req;

	p9_debug(TRANS, "client %p op %d\n", c, type);

	/* we allow for any status other than disconnected */
	if (c->status == Disconnected)
		return NULL;

	/* if status is begin_disconnected we allow only clunk request */
	if ((c->status == BeginDisconnect) && (type != P9PROTO_TCLUNK))
		return NULL;

	req = p9_get_request();
	if (req == NULL)
	{
		return NULL;
	}

	/* marshall the data */
	p9pdu_prepare(req->tc, type);
	err = p9pdu_vwritef(req->tc, c->proto_version, fmt, ap);
	if (err)
		goto reterr;
	p9pdu_finalize(c, req->tc);
	return req;
reterr:
	p9_free_req(req);
	return NULL;
}

static struct p9_req_t *
p9_client_request(struct p9_client *c, int8_t type, const char *fmt, ...)
{
	va_list ap;
	int err;
	struct p9_req_t *req;

	va_start(ap, fmt);
	/* This will get the req . Malloc the request, fill in the fd allocs 
	 * and then send the request for the type. */
	req = p9_client_prepare_req(c, type, c->msize, fmt, ap);
	va_end(ap);

	if (req == NULL)
		return NULL;
	/* Call into the transport for submission. */

	dump_pdu(req->tc);
	dump_pdu(req->rc);

	err = c->trans_mod->request(c, req);
	
	if (err < 0) {
		if (err == -EIO)
			c->status = Disconnected;
		goto reterr;
	}
	/* Before we return the req (receive buffer and process it) 
         * we pre process the header to fill in the rc before calling
	 * into the protocol infra to analyze the data.
	 */
	err = p9_client_check_return(c, req);	
	if (err < 0) {
		if (err == -EIO)
			c->status = Disconnected;
		goto reterr;
	}

	if (!err)
		return req;
reterr:
	p9_free_req(req);
	return NULL;
}

/* For the fid create, just use malloc for now.. 
 * we ll figure out a pool after POC */
/* For every client_walk, start at the root node,and then do
 * a client walk till you find the node you are looking for.
 * similar to a lookup */
struct p9_fid *p9_fid_create(struct p9_client *clnt)
{
	struct p9_fid *fid;

	p9_debug(TRANS, "clnt %p\n", clnt);
	fid = malloc(sizeof(struct p9_fid), M_TEMP, M_WAITOK | M_ZERO);

	if (!fid)
		return NULL;

	/* GET THE unique number from the pool for the file. */
	fid->fid = alloc_unr(clnt->fidpool);

	memset(&fid->qid, 0, sizeof(struct p9_qid));
	fid->mode = -1;
	fid->uid = 0;
	fid->clnt = clnt;
	fid->rdir = NULL;

	return fid;

}

static void p9_fid_destroy(struct p9_fid *fid)
{
	struct p9_client *clnt;

	p9_debug(TRANS, "fid %d\n", fid->fid);
	clnt = fid->clnt;
	free(fid, M_TEMP);
}

/* Send a request to the server to find the proto_version*/
int p9_client_version(struct p9_client *c)
{
	int err = 0;
	struct p9_req_t *req;
	char *version;
	int msize;

	p9_debug(TRANS, ">>> TVERSION msize %d protocol %d\n",
		 c->msize, c->proto_version);

	switch (c->proto_version) {
	case p9_proto_2000L:
		req = p9_client_request(c, P9PROTO_TVERSION, "ds",
					c->msize, "9P2000.L");
		break;
	case p9_proto_2000u:
		req = p9_client_request(c, P9PROTO_TVERSION, "ds",
					c->msize, "9P2000.u");
		break;
	case p9_proto_legacy:
		req = p9_client_request(c, P9PROTO_TVERSION, "ds",
					c->msize, "9P2000");
		break;
	default:
		return -EINVAL;
	}

	if (req == NULL)
		return -ENOMEM;

	err = p9pdu_readf(req->rc, c->proto_version, "ds", &msize, &version);
	if (err) {
		p9_debug(TRANS, "version error %d\n", err);
		goto error;
	}

	p9_debug(TRANS, "<<< RVERSION msize %d %s\n", msize, version);

	if (!strncmp(version, "9P2000.L", 8))
		c->proto_version = p9_proto_2000L;
	else if (!strncmp(version, "9P2000.u", 8))
		c->proto_version = p9_proto_2000u;
	else if (!strncmp(version, "9P2000", 6))
		c->proto_version = p9_proto_legacy;
	else {
		err = -ENOMEM;
		goto error;
	}

	/* limit the msize .*/
	if (msize < c->msize)
		c->msize = msize;

error:
	p9_free_req(req);

	return err;
}

#define INT_MAX 1024 // This is the max inode number.
/* Return the client to the session in the FS to hold it */
struct p9_client *
p9_client_create(struct mount *mp)
{
	int err = 0;
	struct p9_client *clnt = NULL;

	clnt = malloc(sizeof(struct p9_client), M_TEMP, M_WAITOK | M_ZERO);
	if (!clnt)
		goto bail_out;

	clnt->trans_mod = NULL;
	clnt->trans = NULL;


	/* Parse should have set trans_mod */
	err = p9_parse_opts(mp, clnt);
	if (err < 0)
		goto bail_out;

	if (clnt->trans_mod == NULL)
		clnt->trans_mod = p9_get_default_trans();

	if (clnt->trans_mod == NULL) {
		err = -EPROTONOSUPPORT;
		p9_debug(TRANS,
			 "No transport defined or default transport\n");
		goto bail_out;
	}

	// Init the request_pool .
	//allocator_pool_init(clnt);

	clnt->fidpool = new_unrhdr(2, INT_MAX, NULL);
	if (!(clnt->fidpool)) {
		err = -ENOMEM;
		goto bail_out;
	}

	p9_debug(TRANS, "clnt %p trans %p msize %d protocol %d\n",
		 clnt, clnt->trans_mod, clnt->msize, clnt->proto_version);

	/* For now avoiding any dev_names being passed from the mount */
	err = clnt->trans_mod->create(clnt);
	if (err) {
		err = -ENOENT;
		goto bail_out;
	}

       	/* Init the client lock */
        P9CLNT_INIT(clnt);
        /* Init the request lock for submission */
        P9REQ_INIT(clnt);
	printf("Locks init done ..\n");

	err = p9_client_version(clnt);
	if (err)
		goto bail_out;

	printf("Client creation success .\n");

	return clnt;

bail_out:
	if (err == -ENOENT)
	clnt->trans_mod->close(clnt);
	if (clnt)
	free(clnt, M_TEMP);

	return NULL;
}

void p9_client_destroy(struct p9_client *clnt)
{
	p9_debug(TRANS, "clnt %p\n", clnt);

	if (clnt->trans_mod)
		clnt->trans_mod->close(clnt);

	p9_put_trans(clnt->trans_mod);

	if (clnt->fidpool)
		delete_unrhdr(clnt->fidpool);

        free(clnt ,M_TEMP);
}

void p9_client_disconnect(struct p9_client *clnt)
{
	p9_debug(TRANS, "clnt %p\n", clnt);
	clnt->status = Disconnected;
}

void p9_client_begin_disconnect(struct p9_client *clnt)
{
	p9_debug(TRANS, "clnt %p\n", clnt);
	clnt->status = BeginDisconnect;
}


/*
struct p9_fid {
        struct p9_client *clnt;
        uint32_t fid;
        int mode;
        struct p9_qid qid;
        uint32_t iounit;
        uid_t uid;
        void *rdir;
}; */


static 
void dump_fid(struct p9_fid *fid)
{
	printf("<<<DUMP_FID \n");
	printf("fid_num :%u %d %d\n",fid->fid,fid->mode,fid->uid);
}

/* This is called from the mount. This fid which is created for the root inode.
 * the other instances already have the afid .
 */
struct p9_fid *p9_client_attach(struct p9_client *clnt)
{
	/* OK there is big hole here ?  WE have to
	 * use err somewher , otherise it doesnt make
	  * much sense .. we should return that from here */
	int err = 0;
	struct p9_req_t *req;
	struct p9_fid *fid = NULL;
	struct p9_qid qid;
	char uname[7] ="nobody";
	char aname[1] = "";

	p9_debug(TRANS, ">>> TATTACH \n");
	fid = p9_fid_create(clnt);
	if (fid == NULL) {
		err = -ENOMEM;
		fid = NULL;
		goto error;
	}
	fid->uid = -1;
	dump_fid(fid);

	/* Get uname from mount and stick it in this function. */
	req = p9_client_request(clnt, P9PROTO_TATTACH, "ddssd", fid->fid,
			P9PROTO_NOFID, uname, aname, fid->uid);

	if (req == NULL) {
		goto error;
	}

	err = p9pdu_readf(req->rc, clnt->proto_version, "Q", &qid);

	if (err) {
		p9_free_req(req);
		goto error;
	}

	p9_debug(TRANS, "<<< RATTACH qid %x.%llx.%x\n",
		 qid.type, (unsigned long long)qid.path, qid.version);

	memmove(&fid->qid, &qid, sizeof(struct p9_qid));

	p9_free_req(req);
	return fid;

error:
	if (fid)
		p9_fid_destroy(fid);
	return NULL;
}

/* This is client_detach. This is called as the shutdown/unmount process. */
int p9_client_detach(struct p9_fid *fid)
{
	int err;
	struct p9_client *clnt;
	struct p9_req_t *req;

	p9_debug(TRANS, ">>> TREMOVE fid %d\n", fid->fid);
	err = 0;
	clnt = fid->clnt;

	req = p9_client_request(clnt, P9PROTO_TREMOVE, "d", fid->fid);
	if (req == NULL) {
		err = -ENOMEM;
		goto error;
	}

	p9_debug(TRANS, "<<< RREMOVE fid %d\n", fid->fid);

	p9_free_req(req);
error:
	if (err == -ENOSPC)
		p9_client_close(fid);
	else
		p9_fid_destroy(fid);
	return err;
}

/* When an extra fid has been created on the qemu and we found errors, we are going
 * to clunk the fid again and free the fid to return ENOENT (ex from lookup to reflect
 * that
 */
static int 
p9_client_clunk(struct p9_fid *fid)
{
        int err;
        struct p9_client *clnt;
        struct p9_req_t *req;

        if (!fid) {
                p9_debug(TRANS, "clunk with NULL fid is bad\n");
                return 0;
        }

        p9_debug(TRANS, ">>> TCLUNK fid %d \n", fid->fid);

        err = 0;
        clnt = fid->clnt;

        req = p9_client_request(clnt, P9PROTO_TCLUNK, "d", fid->fid);
        if (req == NULL) {
                err = -ENOMEM;
                goto error;
        }

        p9_debug(TRANS, "<<< RCLUNK fid %d\n", fid->fid);

        p9_free_req(req);
error:
        p9_fid_destroy(fid);

        return err;
}

/* oldfid is the fid of the directory. We need to search the component name
 * present in wnames 
 */
struct p9_fid *p9_client_walk(struct p9_fid *oldfid, uint16_t nwname,
		char **wnames, int clone)
{
	int err;
	struct p9_client *clnt;
	struct p9_fid *fid;
	struct p9_qid *wqids;
	struct p9_req_t *req;
	uint16_t nwqids, count;

	err = 0;
	wqids = NULL;
	clnt = oldfid->clnt;
	if (clone) {
		fid = p9_fid_create(clnt);
		if (fid == NULL) {
			err = -ENOMEM;
			fid = NULL;
			goto error;
		}

		fid->uid = oldfid->uid;
	} else
		fid = oldfid;

	p9_debug(TRANS, ">>> TWALK fids %d,%d nwname %ud wname[0] %s\n",
		 oldfid->fid, fid->fid, nwname, wnames ? wnames[0] : NULL);

	/* the newfid is for the component in search. We are preallocating as qemu
	 * on the other side allocates or returns a fid if it sees a match
	 */
	req = p9_client_request(clnt, P9PROTO_TWALK, "ddT", oldfid->fid, fid->fid,
								nwname, wnames);
	if (req == NULL) {
		err = -ENOMEM;
		goto error;
	}

	err = p9pdu_readf(req->rc, clnt->proto_version, "R", &nwqids, &wqids);
	if (err) {
		p9_free_req(req);
		goto clunk_fid;
	}
	p9_free_req(req);

	p9_debug(TRANS, "<<< RWALK nwqid %d:\n", nwqids);

	if (nwqids != nwname) {
		err = -ENOENT;
		goto clunk_fid;
	}

	for (count = 0; count < nwqids; count++)
		p9_debug(TRANS, "<<<     [%d] %x.%llx.%x\n",
			count, wqids[count].type,
			(unsigned long long)wqids[count].path,
			wqids[count].version);

	if (nwname)
		memmove(&fid->qid, &wqids[nwqids - 1], sizeof(struct p9_qid));
	else
		fid->qid = oldfid->qid;

	free(wqids, M_TEMP);
	return fid;

clunk_fid:
	free(wqids, M_TEMP);
	p9_client_clunk(fid);
	fid = NULL;

error:
	if (fid && (fid != oldfid))
		p9_fid_destroy(fid);

	return NULL;
}

/* FIleops supported for now .*/
int p9_client_open(struct p9_fid *fid, int mode)
{
	int err;
	struct p9_client *clnt;
	struct p9_req_t *req;
	struct p9_qid qid;
	int iounit;

	clnt = fid->clnt;
	p9_debug(TRANS, ">>> %s fid %d mode %d\n",
		p9_is_proto_dotl(clnt) ? "TLOPEN" : "TOPEN", fid->fid, mode);
	err = 0;

	if (fid->mode != -1)
		return -EINVAL;

	if (p9_is_proto_dotl(clnt))
		req = p9_client_request(clnt, P9PROTO_TLOPEN, "dd", fid->fid, mode);
	else
		req = p9_client_request(clnt, P9PROTO_TOPEN, "db", fid->fid, mode);
	if (req == NULL) {
		return -ENOMEM;
	}

	err = p9pdu_readf(req->rc, clnt->proto_version, "Qd", &qid, &iounit);
	if (err) {
		err = -EINVAL;
		goto free_and_error;
	}

	p9_debug(TRANS, "<<< %s qid %x.%llx.%x iounit %x\n",
		p9_is_proto_dotl(clnt) ? "RLOPEN" : "ROPEN",  qid.type,
		(unsigned long long)qid.path, qid.version, iounit);

	fid->mode = mode;
	fid->iounit = iounit;
	/* COpy the qid into the opened fid .*/
	memcpy(&fid->qid, &qid, sizeof(qid));

free_and_error:
	p9_free_req(req);
	return err;
}

int p9_client_close(struct p9_fid *fid)
{
	printf("%s: XXX not implemented\n", __func__);
	return 0;
}

struct p9_wstat *p9_client_stat(struct p9_fid *fid)
{
	int err = 0;
	struct p9_client *clnt;
	struct p9_wstat *ret = malloc(sizeof(struct p9_wstat) ,M_TEMP,  M_WAITOK | M_ZERO);
	struct p9_req_t *req;
	uint16_t ignored;

	p9_debug(TRANS, ">>> TSTAT fid %d\n", fid->fid);

	clnt = fid->clnt;

	req = p9_client_request(clnt, P9PROTO_TSTAT, "d", fid->fid);
	if (req == NULL) {
		goto error;
	}

	err = p9pdu_readf(req->rc, clnt->proto_version, "wS", &ignored, ret);
	if (err) {
		p9_free_req(req);
		goto error;
	}

	p9_free_req(req);
	return ret;

error:
	free(req, M_TEMP);
	return NULL;
}

static int p9_client_statsize(struct p9_wstat *wst, int proto_version)
{
	int ret;

	/* NOTE: size shouldn't include its own length */
	/* size[2] type[2] dev[4] qid[13] */
	/* mode[4] atime[4] mtime[4] length[8]*/
	/* name[s] uid[s] gid[s] muid[s] */
	ret = 2+4+13+4+4+4+8+2+2+2+2;

	if (wst->name)
		ret += strlen(wst->name);
	if (wst->uid)
		ret += strlen(wst->uid);
	if (wst->gid)
		ret += strlen(wst->gid);
	if (wst->muid)
		ret += strlen(wst->muid);

	if ((proto_version == p9_proto_2000u) ||
		(proto_version == p9_proto_2000L)) {
		ret += 2+4+4+4;	/* extension[s] n_uid[4] n_gid[4] n_muid[4] */
		if (wst->extension)
			ret += strlen(wst->extension);
	}

	return ret;
}

int p9_client_wstat(struct p9_fid *fid, struct p9_wstat *wst)
{
	int err;
	struct p9_req_t *req;
	struct p9_client *clnt;

	err = 0;
	clnt = fid->clnt;
	wst->size = p9_client_statsize(wst, clnt->proto_version);

	req = p9_client_request(clnt, P9PROTO_TWSTAT, "dwS", fid->fid, wst->size+2, wst);
	if (req == NULL) {
		err = -ENOMEM;
		goto error;
	}

	p9_free_req(req);
error:
	return err;
}


/* This gets the disk info from the host for the fid mentioned. */
struct p9_stat_dotl *p9_client_getattr_dotl(struct p9_fid *fid,
							uint64_t request_mask)
{
	int err;
	struct p9_client *clnt;
	struct p9_stat_dotl *ret = malloc(sizeof(struct p9_stat_dotl), M_TEMP, M_WAITOK | M_ZERO);
	struct p9_req_t *req;

	p9_debug(TRANS, ">>> TGETATTR fid %d, request_mask %ld\n",
							fid->fid, request_mask);
	if (!ret)
		return NULL;

	err = 0;
	clnt = fid->clnt;

	req = p9_client_request(clnt, P9PROTO_TGETATTR, "dq", fid->fid, request_mask);
	if (req ==  NULL) {
		err =-ENOMEM;
		goto error;
	}

	err = p9pdu_readf(req->rc, clnt->proto_version, "A", ret);
	if (err) {
		p9_free_req(req);
		goto error;
	}

	p9_debug(TRANS,
		"<<< RGETATTR st_result_mask=%ld\n"
		"<<< qid=%x.%lx.%x\n"
		"<<< st_mode=%8.8x st_nlink=%lu\n"
		"<<< st_rdev=%lx st_size=%lx st_blksize=%lu st_blocks=%lu\n"
		"<<< st_atime_sec=%ld st_atime_nsec=%ld\n"
		"<<< st_mtime_sec=%ld st_mtime_nsec=%ld\n"
		"<<< st_ctime_sec=%ld st_ctime_nsec=%ld\n"
		"<<< st_btime_sec=%ld st_btime_nsec=%ld\n"
		"<<< st_gen=%ld st_data_version=%ld",
		ret->st_result_mask, ret->qid.type, ret->qid.path,
		ret->qid.version, ret->st_mode, ret->st_nlink,
		ret->st_rdev, ret->st_size, ret->st_blksize,
		ret->st_blocks, ret->st_atime_sec, ret->st_atime_nsec,
		ret->st_mtime_sec, ret->st_mtime_nsec, ret->st_ctime_sec,
		ret->st_ctime_nsec, ret->st_btime_sec, ret->st_btime_nsec,
		ret->st_gen, ret->st_data_version);

	p9_free_req(req);
	return ret;

error:
	free(ret, M_TEMP);
	return NULL;
}

int p9_client_setattr(struct p9_fid *fid, struct p9_iattr_dotl *p9attr)
{
	int err;
	struct p9_req_t *req;
	struct p9_client *clnt;

	err = 0;
	clnt = fid->clnt;
	p9_debug(TRANS, ">>> TSETATTR fid %d\n", fid->fid);
	p9_debug(TRANS,
		"    valid=%x mode=%x size=%ld\n"
		"    atime_sec=%ld atime_nsec=%ld\n"
		"    mtime_sec=%ld mtime_nsec=%ld\n",
		p9attr->valid, p9attr->mode,
		p9attr->size, p9attr->atime_sec, p9attr->atime_nsec,
		p9attr->mtime_sec, p9attr->mtime_nsec);

	req = p9_client_request(clnt, P9PROTO_TSETATTR, "dI", fid->fid, p9attr);

	if (req == NULL) {
		err = -ENOMEM;
		goto error;
	}
	p9_debug(TRANS, "<<< RSETATTR fid %d\n", fid->fid);
	p9_free_req(req);
error:
	return err;
}

int p9_client_statfs(struct p9_fid *fid, struct p9_rstatfs *sb)
{
	int err;
	struct p9_req_t *req;
	struct p9_client *clnt;

	err = 0;
	clnt = fid->clnt;

	p9_debug(TRANS, ">>> TSTATFS fid %d\n", fid->fid);

	req = p9_client_request(clnt, P9PROTO_TSTATFS, "d", fid->fid);
	if (req == NULL) {
		err = -ENOMEM;
		goto error;
	}

	err = p9pdu_readf(req->rc, clnt->proto_version, "ddqqqqqqd", &sb->type,
		&sb->bsize, &sb->blocks, &sb->bfree, &sb->bavail,
		&sb->files, &sb->ffree, &sb->fsid, &sb->namelen);
	if (err) {
		p9_free_req(req);
		goto error;
	}

	p9_debug(TRANS, "<<< RSTATFS fid %d type 0x%lx bsize %ld "
		"blocks %lu bfree %lu bavail %lu files %lu ffree %lu "
		"fsid %lu namelen %ld\n",
		fid->fid, (long unsigned int)sb->type, (long int)sb->bsize,
		sb->blocks, sb->bfree, sb->bavail, sb->files,  sb->ffree,
		sb->fsid, (long int)sb->namelen);

	p9_free_req(req);
error:
	return err;
}

/* Only support for readdir for now .*/ 
int p9_client_readdir(struct p9_fid *fid, char *data, uint32_t count, uint64_t offset)
{
	int err;
	struct p9_client *clnt;
	struct p9_req_t *req = NULL;
	char *dataptr;
	int size;

	p9_debug(TRANS, ">>> TREADDIR fid %d offset %llu count %d\n",
				fid->fid, (unsigned long long) offset, count);

	err = 0;
	clnt = fid->clnt;

	size = clnt->msize;

	req = p9_client_request(clnt, P9PROTO_TREADDIR, "dqd", fid->fid,
			    offset, size);
	if (req == NULL) {
		err = -ENOMEM;
		goto error;
	}

	err = p9pdu_readf(req->rc, clnt->proto_version, "D", &count, &dataptr);
	if (err) {
		goto free_and_error;
	}

	p9_debug(TRANS, "<<< RREADDIR count %d\n", count);

	/* COpy back the data into the input buffer. */
	memmove(data, dataptr, count);

	p9_free_req(req);
	return count;

free_and_error:
	p9_free_req(req);
error:
	return err;
}
