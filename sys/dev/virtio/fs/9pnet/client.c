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
 * 9P Client API
 */

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

static MALLOC_DEFINE(M_P9REQ, "p9_req_t", "Request structures for virtfs");

static MALLOC_DEFINE(M_P9FID, "p9_fid", "Fid (FILE ID) structures for virtfs");

static struct p9_req_t *
p9_client_request(struct p9_client *c, int8_t type, const char *fmt, ...);
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

	/* These are defaults for now */
	clnt->proto_version = p9_proto_2000u;
	clnt->msize = 8192;

    	trans = vfs_getopts(mp->mnt_optnew, "trans", &error);
    	if (error)
        	return (error);

	p9_debug(TRANS, " Attaching to the %s transport \n",trans);
	/*
         * This will be moved to mod where we can have multiple entries in the
	 * table to search for and return the correct pointer. For now just get
         * the default virtio_ops.
	 */
    	clnt->trans_mod = p9_get_default_trans();
    	if (clnt->trans_mod == NULL) {
            	p9_debug(TRANS, "Could not find request transport: %s\n",trans);
            	error = EINVAL;
        }
	return error;
}

static struct p9_buffer *
p9_buffer_alloc(int alloc_msize)
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

static void
p9_free_req(struct p9_req_t *req)
{
	if (req->tc)
		p9_buffer_free(req->tc);
	if (req->rc)
		p9_buffer_free(req->rc);

	free(req, M_P9REQ);
}

struct p9_req_t *
p9_get_request(void)
{
	struct p9_req_t *req;
	int alloc_msize = MTU;

	req = malloc(sizeof(*req), M_P9REQ, M_WAITOK | M_ZERO);
	if (req == NULL) return NULL;
	if (!req->tc)
		req->tc = p9_buffer_alloc(alloc_msize);
	if (!req->rc) {
		req->rc = p9_buffer_alloc(alloc_msize);
	}

	if (req->tc == NULL || req->rc == NULL)
		return NULL;
	return req;
}

#if 0
static void
dump_buf(struct p9_buffer *buf)
{
	/* Char buffer */
	int i;
	char *tbuf = &buf->sdata[0];
	/* Just dump 30 character of the buf */

	//printf("buf->sdata[0] address %p \n",&tbuf[0]);
	/*Dump all the first 30 characters */
	for(i=0;i<30;i++)
		printf("%hhu ",tbuf[i]);
}
#endif

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

	//dump_buf(buf);

	/* This is the initial header parse. size, type, and tag .*/
        err = p9_buf_readf(buf, 0, "dbw", &size, &type, &tag);
        if (err)
                goto exit;

        buf->size = size;
        buf->id = type;
        buf->tag = tag;

        p9_debug(TRANS, "size=%d type: %d tag: %d\n",
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

	//dump_buf(req->tc);
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
        err = p9_buf_readf(req->rc, c->proto_version, "d", &ecode);
        err = ecode;

        p9_debug(TRANS, "RLERROR (%d)\n", -ecode);

        return err;
}

static struct p9_req_t *p9_client_prepare_req(struct p9_client *c,
					      int8_t type, int req_size,
					      const char *fmt, __va_list ap)
{
	int err;
	struct p9_req_t *req;

	p9_debug(TRANS, "client %p op %d\n", c, type);

	req = p9_get_request();
	if (req == NULL)
	{
		return NULL;
	}

	/* Marshall the data according to QEMU stds */
	p9_buf_prepare(req->tc, type);
	err = p9_buf_vwritef(req->tc, c->proto_version, fmt, ap);
	if (err)
		goto reterr;
	p9_buf_finalize(c, req->tc);
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
	req = p9_client_prepare_req(c, type, c->msize, fmt, ap);
	va_end(ap);

	if (req == NULL)
		return NULL;

	//dump_buf(req->tc);
	//dump_buf(req->rc);

	/* Call into the transport for submission. */
	err = c->trans_mod->request(c, req);

	if (err)
		goto error;
	/* Before we return the req (receive buffer and process it)
         * we pre process the header to fill in the rc before calling
	 * into the protocol infra to analyze the data.
	 */
	err = p9_client_check_return(c, req);
	if (err)
		goto error;

	if (!err)
		return req;
error:
	p9_free_req(req);
	return NULL;
}

struct p9_fid *
p9_fid_create(struct p9_client *clnt)
{
	struct p9_fid *fid;

	p9_debug(TRANS, "clnt %p\n", clnt);

	fid = malloc(sizeof(struct p9_fid), M_P9FID, M_WAITOK | M_ZERO);

	if (!fid)
		return NULL;

	fid->fid = alloc_unr(clnt->fidpool);
	memset(&fid->qid, 0, sizeof(struct p9_qid));
	fid->mode = -1;
	fid->uid = 0;
	fid->clnt = clnt;

	return fid;
}

void
p9_fid_destroy(struct p9_fid *fid)
{
	struct p9_client *clnt;

	p9_debug(TRANS, "fid %d\n", fid->fid);
	clnt = fid->clnt;
	/* Release to the pool */
	free_unr(clnt->fidpool, fid->fid);
	free(fid, M_P9FID);
}

int p9_client_version(struct p9_client *c)
{
	int err = 0;
	struct p9_req_t *req;
	char *version;
	int msize;

	p9_debug(TRANS, "TVERSION msize %d protocol %d\n",
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
		return EINVAL;
	}

	if (req == NULL)
		return ENOMEM;

	err = p9_buf_readf(req->rc, c->proto_version, "ds", &msize, &version);
	if (err) {
		p9_debug(TRANS, "version error %d\n", err);
		goto error;
	}

	p9_debug(TRANS, "RVERSION msize %d %s\n", msize, version);

	if (!strncmp(version, "9P2000.L", 8))
		c->proto_version = p9_proto_2000L;
	else if (!strncmp(version, "9P2000.u", 8))
		c->proto_version = p9_proto_2000u;
	else if (!strncmp(version, "9P2000", 6))
		c->proto_version = p9_proto_legacy;
	else {
		err = ENOMEM;
		goto error;
	}

	/* limit the msize .*/
	if (msize < c->msize)
		c->msize = msize;

error:
	p9_free_req(req);

	return err;
}

#define INT_MAX 1024  * 1024 // max inode.
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

	/*Allocate the io buffer */
	clnt->io_buffer = malloc(clnt->msize, M_TEMP, M_WAITOK | M_ZERO);
	if (clnt->io_buffer == NULL)
		goto bail_out;

	if (clnt->trans_mod == NULL) {
		err = EINVAL;
		p9_debug(TRANS, "No transport defined or default transport\n");
		goto bail_out;
	}

	clnt->fidpool = new_unrhdr(2, INT_MAX, NULL);
	if (!(clnt->fidpool)) {
		err = ENOMEM;
		goto bail_out;
	}

	p9_debug(TRANS, "clnt %p trans %p msize %d protocol %d\n",
		 clnt, clnt->trans_mod, clnt->msize, clnt->proto_version);

	err = clnt->trans_mod->create(clnt);
	if (err) {
		err = ENOENT;
		goto bail_out;
	}

       	/* Init the client lock */
        P9CLNT_INIT(clnt);
        /* Init the request lock for submission */
        P9REQ_INIT(clnt);

	err = p9_client_version(clnt);
	if (err)
		goto bail_out;

	p9_debug(TRANS, "Client creation success .\n");

	return clnt;

bail_out:
	if (clnt)
	free(clnt, M_TEMP);

	return NULL;
}

void
p9_client_destroy(struct p9_client *clnt)
{
	p9_debug(TRANS, "clnt %p\n", clnt);

	p9_put_trans(clnt->trans_mod);

	if (clnt->fidpool)
		delete_unrhdr(clnt->fidpool);

	if (clnt->io_buffer)
		free(clnt->io_buffer, M_TEMP);

        free(clnt ,M_TEMP);
}

#if 0
static
void dump_fid(struct p9_fid *fid)
{
	printf("<<<DUMP_FID \n");
	printf("fid_num :%u %d %d\n",fid->fid,fid->mode,fid->uid);
}
#endif

/*
 * Called from mount. fid returned is created for the root inode.
 * the other instances already have the afid.
 */
struct p9_fid *p9_client_attach(struct p9_client *clnt)
{
	int err = 0;
	struct p9_req_t *req;
	struct p9_fid *fid = NULL;
	struct p9_qid qid;
	char uname[7] ="nobody";
	char aname[1] = "";

	p9_debug(TRANS, " TATTACH \n");
	fid = p9_fid_create(clnt);
	if (fid == NULL) {
		err = ENOMEM;
		fid = NULL;
		goto error;
	}
	fid->uid = -1;
	//dump_fid(fid);

	req = p9_client_request(clnt, P9PROTO_TATTACH, "ddssd", fid->fid,
			P9PROTO_NOFID, uname, aname, fid->uid);

	if (req == NULL) {
		goto error;
	}

	err = p9_buf_readf(req->rc, clnt->proto_version, "Q", &qid);

	if (err) {
		p9_free_req(req);
		goto error;
	}

	p9_debug(TRANS, "RATTACH qid %x.%llx.%x\n",
		 qid.type, (unsigned long long)qid.path, qid.version);

	memmove(&fid->qid, &qid, sizeof(struct p9_qid));
	p9_free_req(req);

	return fid;

error:
	if (fid)
		p9_fid_destroy(fid);
	return NULL;
}

int
p9_client_remove(struct p9_fid *fid)
{
	int err;
	struct p9_client *clnt;
	struct p9_req_t *req;

	p9_debug(TRANS, "TREMOVE fid %d\n", fid->fid);
	err = 0;
	clnt = fid->clnt;

	req = p9_client_request(clnt, P9PROTO_TREMOVE, "d", fid->fid);
	if (req == NULL) {
		err = ENOMEM;
		goto error;
	}

	p9_debug(TRANS, "RREMOVE fid %d\n", fid->fid);

	p9_free_req(req);
error:
	if (err == ENOSPC)
		p9_client_close(fid);
	else
		p9_fid_destroy(fid);
	return err;
}

/*
 * When an extra fid has been created on the qemu and we found errors, we are going
 * to clunk the fid again and free the fid to return ENOENT (ex from lookup to reflect
 * that
 */
int
p9_client_clunk(struct p9_fid *fid)
{
        int err = 0;
        struct p9_client *clnt;
        struct p9_req_t *req;

        if (!fid) {
                p9_debug(TRANS, "clunk with NULL fid is bad\n");
                return 0;
        }

        p9_debug(TRANS, "TCLUNK fid %d \n", fid->fid);

        err = 0;
        clnt = fid->clnt;

        req = p9_client_request(clnt, P9PROTO_TCLUNK, "d", fid->fid);
        if (req == NULL) {
                err = ENOMEM;
                goto error;
        }

        p9_debug(TRANS, "RCLUNK fid %d\n", fid->fid);

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
			err = ENOMEM;
			fid = NULL;
			goto error;
		}

		fid->uid = oldfid->uid;
	} else
		fid = oldfid;

	p9_debug(TRANS, "TWALK fids %d,%d nwname %ud wname[0] %s\n",
		 oldfid->fid, fid->fid, nwname, wnames ? wnames[0] : NULL);

	/* the newfid is for the component in search. We are preallocating as qemu
	 * on the other side allocates or returns a fid if it sees a match
	 */
	req = p9_client_request(clnt, P9PROTO_TWALK, "ddT", oldfid->fid, fid->fid,
								nwname, wnames);
	if (req == NULL) {
		err = ENOMEM;
		goto error;
	}

	err = p9_buf_readf(req->rc, clnt->proto_version, "R", &nwqids, &wqids);
	if (err) {
		p9_free_req(req);
		goto clunk_fid;
	}
	p9_free_req(req);

	p9_debug(TRANS, "RWALK nwqid %d:\n", nwqids);

	if (nwqids != nwname) {
		err = ENOENT;
		goto clunk_fid;
	}

	for (count = 0; count < nwqids; count++)
		p9_debug(TRANS, "[%d] %x.%llx.%x\n",
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

/* Fileops */
int p9_client_open(struct p9_fid *fid, int mode)
{
	int err;
	struct p9_client *clnt;
	struct p9_req_t *req;
	struct p9_qid qid;
	int mtu = 0;

	clnt = fid->clnt;
	p9_debug(TRANS, "%s fid %d mode %d\n",
		p9_is_proto_dotl(clnt) ? "TLOPEN" : "TOPEN", fid->fid, mode);
	err = 0;

	if (fid->mode != -1)
		return EINVAL;

	if (p9_is_proto_dotl(clnt))
		req = p9_client_request(clnt, P9PROTO_TLOPEN, "dd", fid->fid, mode);
	else
		req = p9_client_request(clnt, P9PROTO_TOPEN, "db", fid->fid, mode);
	if (req == NULL) {
		return ENOMEM;
	}

	err = p9_buf_readf(req->rc, clnt->proto_version, "Qd", &qid, &mtu);
	if (err) {
		err = EINVAL;
		goto out;
	}

	p9_debug(TRANS, " %s qid %x.%llx.%x mtu %x\n",
		p9_is_proto_dotl(clnt) ? "RLOPEN" : "ROPEN",  qid.type,
		(unsigned long long)qid.path, qid.version, mtu);

	fid->mode = mode;
	fid->mtu = mtu;
	/* Copy the qid into the opened fid .*/
	memcpy(&fid->qid, &qid, sizeof(qid));
out:
	p9_free_req(req);
	return err;
}

struct p9_wstat *p9_client_stat(struct p9_fid *fid)
{
	int err = 0;
	struct p9_client *clnt;
	struct p9_wstat *stat;
	struct p9_req_t *req;
	uint16_t ignored;

	stat = malloc(sizeof(struct p9_wstat) ,M_TEMP,  M_WAITOK | M_ZERO);
	if (stat == NULL) {
		goto error;
	}
	p9_debug(TRANS, "TSTAT fid %d\n", fid->fid);

	clnt = fid->clnt;

	req = p9_client_request(clnt, P9PROTO_TSTAT, "d", fid->fid);
	if (req == NULL) {
		goto error;
	}

	err = p9_buf_readf(req->rc, clnt->proto_version, "wS", &ignored, stat);
	if (err) {
		p9_free_req(req);
		goto error;
	}

	p9_free_req(req);
	return stat;

error:
	if (req)
		p9_free_req(req);
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

/* Write wstat. Called mostly by setattr*/
int p9_client_wstat(struct p9_fid *fid, struct p9_wstat *wst)
{
	int err;
	struct p9_req_t *req;
	struct p9_client *clnt;

	err = 0;
	clnt = fid->clnt;
	/*Computing the size as we have variable sized strings */
	wst->size = p9_client_statsize(wst, clnt->proto_version);

	req = p9_client_request(clnt, P9PROTO_TWSTAT, "dwS", fid->fid, wst->size+2, wst);
	if (req == NULL) {
		err = ENOMEM;
		goto error;
	}

	p9_free_req(req);
error:
	return err;
}

int
p9_client_readdir(struct p9_fid *fid, char *data, uint64_t offset, uint32_t count)
{
	int err;
	uint32_t rsize;
	struct p9_client *clnt;
	struct p9_req_t *req = NULL;
	char *dataptr;

	p9_debug(TRANS, "TREADDIR fid %d offset %llu count %d\n",
				fid->fid, (unsigned long long) offset, count);

	rsize = fid->mtu;
	clnt = fid->clnt;

	if (!rsize || rsize > clnt->msize)
                  rsize = clnt->msize;

        if (count < rsize)
		rsize = count;

	err = 0;

	printf("count rsize :%u %u\n",count,rsize);

	req = p9_client_request(clnt, P9PROTO_TREADDIR, "dqd", fid->fid,
			    offset, rsize);
	if (req == NULL) {
		err = ENOMEM;
		goto error;
	}

	err = p9_buf_readf(req->rc, clnt->proto_version, "D", &count, &dataptr);
	if (err) {
		goto error;
	}

	p9_debug(TRANS, "RREADDIR count %u\n", count);

	/* Copy back the data into the input buffer. */
	memmove(data, dataptr, count);

	p9_free_req(req);
	return count;
error:
	if (req)
		p9_free_req(req);
	return err;
}

int
p9_client_read(struct p9_fid *fid, uint64_t offset, uint32_t count, char *data)
{
	struct p9_client *clnt = fid->clnt;
	struct p9_req_t *req;
	char *dataptr;
	int error = 0;
	int rsize;

	p9_debug(TRANS, "TREAD fid %d offset %llu %u\n",
		   fid->fid, (unsigned long long) offset, count);

	rsize = fid->mtu;
        if (!rsize || rsize > clnt->msize)
                  rsize = clnt->msize;

        if (count < rsize)
		rsize = count;

	/* At this stage, we only have 8K buffers so only transfer */
	req = p9_client_request(clnt, P9PROTO_TREAD, "dqd", fid->fid, offset,
				   rsize);
	if (req == NULL) {
		error = ENOMEM;
		goto error;
	}

	error = p9_buf_readf(req->rc, clnt->proto_version,
			   "D", &count, &dataptr);
	if (error) {
		p9_free_req(req);
		goto error;
	}

      	if (rsize < count) {
              p9_debug(TRANS," RREAD count (%d > %d)\n", count, rsize);
              count = rsize;
        }

	p9_debug(TRANS, "RREAD count %d\n", count);
	if (!count) {
		p9_free_req(req);
		error = EIO;
		goto error;
	}

	/* Copy back the data into the input buffer. */
	memmove(data, dataptr, count);

	p9_free_req(req);

	return count;
error:
	if (req)
		p9_free_req(req);
	return error;
}

int
p9_client_write(struct p9_fid *fid, uint64_t offset, uint32_t count, char *data)
{
	struct p9_client *clnt = fid->clnt;
	struct p9_req_t *req;
	int ret = 0;
	int err = 0;
	int rsize;

	p9_debug(TRANS, " TWRITE fid %d offset %llu  %u\n",
				fid->fid, (unsigned long long) offset, count);
	rsize = fid->mtu;
        if (!rsize || rsize > clnt->msize)
                  rsize = clnt->msize;

	/* Limit set by Qemu ,8168 */
	if (count > rsize) {
		count = rsize;
	}

	/* Doing the Data blob instead. If at all we add the zc, we can change it
	 * to uio direct copy.*/
	req = p9_client_request(clnt, P9PROTO_TWRITE, "dqD", fid->fid,
						    offset, count, data);
	if (req == NULL) {
		err = ENOMEM;
		goto error;
	}

	err = p9_buf_readf(req->rc, clnt->proto_version, "d", &ret);
	if (err) {
		p9_debug(TRANS, "Something went wrong in the write\n");
		goto error;
	}

	p9_debug(TRANS, " RWRITE count %d\n", ret);

	if (count < ret) { // Wait ret returned higher ?
              p9_debug(TRANS," RWRITE count BUG(%d > %d)\n", count, ret);
	      ret = count;
	}

	if (!count) {
		err = EIO;
		goto error;
	}

	p9_free_req(req);

	return ret;
error:
	if (req)
		p9_free_req(req);
	return err;
}

int
p9_client_file_create(struct p9_fid *fid, char *name, uint32_t perm, int mode,
                     char *extension)
{
        int err;
        struct p9_client *clnt;
        struct p9_req_t *req;
        struct p9_qid qid;
	int mtu;

        p9_debug(TRANS, "TCREATE fid %d name %s perm %d mode %d\n",
                                                fid->fid, name, perm, mode);
        err = 0;
        clnt = fid->clnt;

        if (fid->mode != -1)
                return EINVAL;

        req = p9_client_request(clnt, P9PROTO_TCREATE, "dsdb?s", fid->fid, name, perm,
                                mode, extension);
	if (req == NULL) {
		err = ENOMEM;
		goto error;
	}

        err = p9_buf_readf(req->rc, clnt->proto_version, "Qd", &qid, &mtu);

	if (err)
		goto error;

        p9_debug(TRANS, "RCREATE qid %x.%llx.%x mtu %x\n",
                                qid.type,
                                (unsigned long long)qid.path,
                                qid.version, mtu);
        fid->mode = mode;
        fid->mtu = mtu;

error:
	if (req)
        	p9_free_req(req);

        return err;
}

int p9_client_statfs(struct p9_fid *fid, struct p9_statfs *stat)
{
	int err;
	struct p9_req_t *req;
	struct p9_client *clnt;

	err = 0;
 	clnt = fid->clnt;

	p9_debug(TRANS, "TSTATFS fid %d\n", fid->fid);

	req = p9_client_request(clnt, P9PROTO_TSTATFS, "d", fid->fid);
	if (req == NULL) {
		err = ENOMEM;
 		goto error;
	}

	err = p9_buf_readf(req->rc, clnt->proto_version, "ddqqqqqqd", &stat->type,
		&stat->bsize, &stat->blocks, &stat->bfree, &stat->bavail,
 		&stat->files, &stat->ffree, &stat->fsid, &stat->namelen);
	if (err) {
		p9_free_req(req);
		goto error;
	}

	p9_debug(TRANS, " STATFS fid %d type 0x%lx bsize %ld "
		"blocks %lu bfree %lu bavail %lu files %lu ffree %lu "
		"fsid %lu namelen %ld\n",
		fid->fid, (long unsigned int)stat->type, (long int)stat->bsize,
		stat->blocks, stat->bfree, stat->bavail, stat->files,  stat->ffree,
		stat->fsid, (long int)stat->namelen);

	p9_free_req(req);
error:
	return err;
}
