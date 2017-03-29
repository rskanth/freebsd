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
 * 9P Protocol Support Code
 * This file provides the standard fot the FS interactions with the Qemu interface as it can understand
 * only this protocol.
 *
 */

#include <sys/types.h>
#include "../9p.h"
#include "../client.h"
#include "../protocol.h"

static int
p9_buf_writef(struct p9_buffer *buf, int proto_version, const char *fmt, ...);
void stat_free(struct p9_wstat *sbuf);

/*static void dump_buf(struct p9_buffer *buf)
{
	printf("size %u id %c tag%u\n",buf->size,buf->id,buf->tag);
	printf("strng%s",&buf->sdata[0]);
	printf("\n");
}*/

void stat_free(struct p9_wstat *stbuf)
{
	free(stbuf->name, M_TEMP);
	free(stbuf->uid, M_TEMP);
	free(stbuf->gid, M_TEMP);
	free(stbuf->muid, M_TEMP);
	free(stbuf->extension, M_TEMP);
}

size_t buf_read(struct p9_buffer *buf, void *data, size_t size)
{
	size_t len = min(buf->size - buf->offset, size);
	//printf("%d %d %d %d sdata %p \n", len, buf->offset,size,buf->size ,&buf->sdata[0]);
	//printf("data in the buf :%hhu %hhu %hhu %hhu \n",buf->sdata[0],buf->sdata[1],buf->sdata[2],buf->sdata[3]);
	memcpy(data, &buf->sdata[buf->offset], len);
	buf->offset += len;
	return size - len;
}

static size_t buf_write(struct p9_buffer *buf, const void *data, size_t size)
{
	size_t len = min(buf->capacity - buf->size, size);
	memcpy(&buf->sdata[buf->size], data, len);
	buf->size += len;
	return size - len;
}

static int
p9_buf_vreadf(struct p9_buffer *buf, int proto_version, const char *fmt,
	va_list ap)
{
	const char *ptr;
	int err = 0;

	for (ptr = fmt; *ptr; ptr++) {
		switch (*ptr) {
		case 'b':{
				int8_t *val = va_arg(ap, int8_t *);
				if (buf_read(buf, val, sizeof(*val))) {
					err = EFAULT;
					break;
				}
			}
			break;
		case 'w':{
				int16_t *val = va_arg(ap, int16_t *);
				if (buf_read(buf, val, sizeof(*val))) {
					err = EFAULT;
					break;
				}
			}
			break;
		case 'd':{
				int32_t *val = va_arg(ap, int32_t *);
				if (buf_read(buf, val, sizeof(*val))) {
					//printf("DId this break \n");
					err = EFAULT;
					break;
				}
				//printf("After sending :%d %d\n",*val,le_val);

			}
			break;
		case 'q':{
				int64_t *val = va_arg(ap, int64_t *);
				if (buf_read(buf, val, sizeof(*val))) {
					err = EFAULT;
					break;
				}
			}
			break;
		case 's':{
				char **sptr = va_arg(ap, char **);
				uint16_t len;

				err = p9_buf_readf(buf, proto_version,
								"w", &len);
				//printf("len should be :%hu \n",len);

				if (err)
					break;

				*sptr = malloc(len + 1, M_TEMP, M_NOWAIT);
				if (*sptr == NULL) {
					//printf("code break at EFAULT ..\n");
					err = EFAULT;
					break;
				}
				if (buf_read(buf, *sptr, len)) {
					err = EFAULT;
					free(*sptr, M_TEMP);
					*sptr = NULL;
				} else
					(*sptr)[len] = 0;
			}
			break;
		case 'Q':{
				struct p9_qid *qid =
				    va_arg(ap, struct p9_qid *);

				err = p9_buf_readf(buf, proto_version, "bdq",
						      &qid->type, &qid->version,
						      &qid->path);
				//printf("done with legit Q read ..\n");
			}
			break;
		case 'S':{
				struct p9_wstat *stbuf =
				    va_arg(ap, struct p9_wstat *);

				memset(stbuf, 0, sizeof(struct p9_wstat));
				stbuf->n_uid = stbuf->n_muid = 0;
				stbuf->n_gid = 0;

				err = p9_buf_readf(buf, proto_version,
						"wwdQdddqssss?sddd",
						&stbuf->size, &stbuf->type,
						&stbuf->dev, &stbuf->qid,
						&stbuf->mode, &stbuf->atime,
						&stbuf->mtime, &stbuf->length,
						&stbuf->name, &stbuf->uid,
						&stbuf->gid, &stbuf->muid,
						&stbuf->extension,
						&stbuf->n_uid, &stbuf->n_gid,
						&stbuf->n_muid);
				if (err)
					stat_free(stbuf);
				//printf("length of file :%lu\n",stbuf->length);
			}
			break;
		case 'D':{
				uint32_t *count = va_arg(ap, uint32_t *);
				void **data = va_arg(ap, void **);

				err = p9_buf_readf(buf, proto_version, "d", count);
				if (!err) {
					*count = MIN(*count,
						  buf->size - buf->offset);
					*data = &buf->sdata[buf->offset];
				}
			}
			break;
		case 'T':{
				uint16_t *nwname = va_arg(ap, uint16_t *);
				char ***wnames = va_arg(ap, char ***);

				err = p9_buf_readf(buf, proto_version,
								"w", nwname);
				if (!err) {
					*wnames = malloc(sizeof(char *) * *nwname, M_TEMP, M_NOWAIT);
					if (!*wnames)
						err = ENOMEM;
				}

				if (!err) {
					int i;

					for (i = 0; i < *nwname; i++) {
						err =
						    p9_buf_readf(buf,
								proto_version,
								"s",
								&(*wnames)[i]);
						if (err)
							break;
					}
				}

				if (err) {
					if (*wnames) {
						int i;

						for (i = 0; i < *nwname; i++)
							free((*wnames)[i], M_TEMP);
					}
					free(*wnames, M_TEMP);
					*wnames = NULL;
				}
			}
			break;
		case 'R':{
				uint16_t *nwqid = va_arg(ap, uint16_t *);
				struct p9_qid **wqids =
				    va_arg(ap, struct p9_qid **);

				*wqids = NULL;

				err = p9_buf_readf(buf, proto_version, "w", nwqid);
				if (!err) {
					*wqids =
					    malloc(*nwqid *
						    sizeof(struct p9_qid), M_TEMP, M_NOWAIT);
					if (*wqids == NULL)
						err = ENOMEM;
				}

				if (!err) {
					int i;

					for (i = 0; i < *nwqid; i++) {
						err =
						    p9_buf_readf(buf,
								proto_version,
								"Q",
								&(*wqids)[i]);
						if (err)
							break;
					}
				}

				if (err) {
					free(*wqids, M_TEMP);
					*wqids = NULL;
				}
			}
			break;
		case 'A': {
				struct p9_stat_dotl *stbuf =
				    va_arg(ap, struct p9_stat_dotl *);

				memset(stbuf, 0, sizeof(struct p9_stat_dotl));
				err = p9_buf_readf(buf, proto_version,
					"qQdugqqqqqqqqqqqqqqq",
					&stbuf->st_result_mask,
					&stbuf->qid,
					&stbuf->st_mode,
					&stbuf->st_uid, &stbuf->st_gid,
					&stbuf->st_nlink,
					&stbuf->st_rdev, &stbuf->st_size,
					&stbuf->st_blksize, &stbuf->st_blocks,
					&stbuf->st_atime_sec,
					&stbuf->st_atime_nsec,
					&stbuf->st_mtime_sec,
					&stbuf->st_mtime_nsec,
					&stbuf->st_ctime_sec,
					&stbuf->st_ctime_nsec,
					&stbuf->st_btime_sec,
					&stbuf->st_btime_nsec,
					&stbuf->st_gen,
					&stbuf->st_data_version);
			}
			break;
		case '?':
			if ((proto_version != p9_proto_2000u) &&
				(proto_version != p9_proto_2000L))
				return 0;
			break;
		default:
			break;
		}

		if (err)
			break;
	}

	return err;
}

int
p9_buf_vwritef(struct p9_buffer *buf, int proto_version, const char *fmt,
	va_list ap)
{
	const char *ptr;
	int err = 0;

	for (ptr = fmt; *ptr; ptr++) {
		switch (*ptr) {
		case 'b':{
				int8_t val = va_arg(ap, int);
				if (buf_write(buf, &val, sizeof(val)))
					err = EFAULT;
				//printf("DId b %u \n",val);
				//printf("size %u id %c tag%u\n",buf->size,buf->id,buf->tag);
				//printf("bit mapint values%hhu \n",buf->sdata[4]);

			}
			break;
		case 'w':{
				int16_t val = va_arg(ap, int);
				if (buf_write(buf, &val, sizeof(val)))
					err = EFAULT;
			}
			break;
		case 'd':{
				int32_t val = va_arg(ap, int32_t);
				//printf("before conversion :%d %d\n",val,buf->size);
				if (buf_write(buf, &val, sizeof(val)))
					err = EFAULT;
					//printf("DId  %d\n",val);
					//printf("size %u id %c tag%u\n",buf->size,buf->id,buf->tag);
					//printf("int values%d %d \n",buf->sdata[0],buf->sdata[5]);

			}
			break;
		case 'q':{
				int64_t val = va_arg(ap, int64_t);
				if (buf_write(buf, &val, sizeof(val)))
					err = EFAULT;
			}
			break;
		case 's':{
				const char *sptr = va_arg(ap, const char *);
				uint16_t len = 0;
				if (sptr)
					len = MIN(strlen(sptr), 16);

				err = p9_buf_writef(buf, proto_version,
								"w", len);
				//printf("DId %s \n",sptr);
				//printf("size %u id %c tag%u\n",buf->size,buf->id,buf->tag);

				if (!err && buf_write(buf, sptr, len))
					err = EFAULT;

				//printf("strng %hhu %hhu %s  \n",buf->sdata[9],buf->sdata[10],&buf->sdata[11]);
			}
			break;
		case 'Q':{
				const struct p9_qid *qid =
				    va_arg(ap, const struct p9_qid *);
				err = p9_buf_writef(buf, proto_version, "bdq",
						 qid->type, qid->version,
						 qid->path);
			} break;
		case 'S':{
				const struct p9_wstat *stbuf =
				    va_arg(ap, const struct p9_wstat *);
				err = p9_buf_writef(buf, proto_version,
						 "wwdQdddqssss?sddd",
						 stbuf->size, stbuf->type,
						 stbuf->dev, &stbuf->qid,
						 stbuf->mode, stbuf->atime,
						 stbuf->mtime, stbuf->length,
						 stbuf->name, stbuf->uid,
						 stbuf->gid, stbuf->muid,
						 stbuf->extension, stbuf->n_uid,
						 stbuf->n_gid, stbuf->n_muid);
			} break;
		case 'D':{
				// WE dont need the return values , these are just values .
				uint32_t count = va_arg(ap, uint32_t);
				void *data = va_arg(ap, void *);
				//printf("Make sure we are hitting the D write .%d\n",count);

				err = p9_buf_writef(buf, proto_version,
								"d", count);
				// Count bytes of the blob into the buf.
				if (!err && buf_write(buf, data, count))
					err = EFAULT;

			}
			break;

		case 'T':{
				uint16_t nwname = va_arg(ap, int);
				const char **wnames = va_arg(ap, const char **);

				err = p9_buf_writef(buf, proto_version, "w",
									nwname);
				if (!err) {
					int i;

					for (i = 0; i < nwname; i++) {
						err =
						    p9_buf_writef(buf,
								proto_version,
								 "s",
								 wnames[i]);
						if (err)
							break;
					}
				}
			}
			break;
		case 'R':{
				uint16_t nwqid = va_arg(ap, int);
				struct p9_qid *wqids =
				    va_arg(ap, struct p9_qid *);

				err = p9_buf_writef(buf, proto_version, "w",
									nwqid);
				if (!err) {
					int i;

					for (i = 0; i < nwqid; i++) {
						err =
						    p9_buf_writef(buf,
								proto_version,
								 "Q",
								 &wqids[i]);
						if (err)
							break;
					}
				}
			}
			break;
		case 'I':{
				struct p9_iattr_dotl *p9attr = va_arg(ap,
							struct p9_iattr_dotl *);

				err = p9_buf_writef(buf, proto_version,
							"ddugqqqqq",
							p9attr->valid,
							p9attr->mode,
							p9attr->uid,
							p9attr->gid,
							p9attr->size,
							p9attr->atime_sec,
							p9attr->atime_nsec,
							p9attr->mtime_sec,
							p9attr->mtime_nsec);
			}
			break;
		case '?':
			if ((proto_version != p9_proto_2000u) &&
				(proto_version != p9_proto_2000L))
				return 0;
			break;
		default:
			break;
		}

		if (err)
			break;
	}

	return err;
}

int p9_buf_readf(struct p9_buffer *buf, int proto_version, const char *fmt, ...)
{
	va_list ap;
	int ret;

	va_start(ap, fmt);
	ret = p9_buf_vreadf(buf, proto_version, fmt, ap);
	va_end(ap);

	return ret;
}

static int
p9_buf_writef(struct p9_buffer *buf, int proto_version, const char *fmt, ...)
{
	va_list ap;
	int ret;

	va_start(ap, fmt);
	ret = p9_buf_vwritef(buf, proto_version, fmt, ap);
	va_end(ap);

	return ret;
}

int p9stat_read(struct p9_client *clnt, char *buf, size_t len, struct p9_wstat *st)
{
	struct p9_buffer msg_buf;
	int ret;

	msg_buf.size = len;
	msg_buf.capacity = len;
	msg_buf.sdata = buf;
	msg_buf.offset = 0;

	ret = p9_buf_readf(&msg_buf, clnt->proto_version, "S", st);
	if (ret) {
		p9_debug(PROTO, "p9stat_read failed: %d\n", ret);
	}

	return ret;
}

int p9_buf_prepare(struct p9_buffer *buf, int8_t type)
{
	int tag = 0;
	buf->id = type;
	//printf("p9_buf_prepare ID%d \n",buf->id);

	return p9_buf_writef(buf, 0, "dbw", 0, type, tag);
}

int p9_buf_finalize(struct p9_client *clnt, struct p9_buffer *buf)
{
	int size = buf->size;
	int err;

	buf->size = 0;
	err = p9_buf_writef(buf, 0, "d", size);
	buf->size = size;

	p9_debug(PROTO, "size=%d type: %d tag: %d\n",
		 buf->size, buf->id, buf->tag);

	return err;
}

void p9_buf_reset(struct p9_buffer *buf)
{
	buf->offset = 0;
	buf->size = 0;
}

/* Directory entry read with the buf we have. Call this once we have the
 * buf to parse .*/
int p9_dirent_read(struct p9_client *clnt, char *buf, int start, int len,
		  struct p9_dirent *dent)
{
	struct p9_buffer msg_buf;
	int ret;
	char *nameptr;
	uint16_t sle;

	msg_buf.size = len;
	msg_buf.capacity = len;
	msg_buf.sdata = buf;
	msg_buf.offset = start;

	ret = p9_buf_readf(&msg_buf, clnt->proto_version, "Qqbs", &dent->qid,
			  &dent->d_off, &dent->d_type, &nameptr);
	if (ret) {
		p9_debug(PROTO, "<<< p9dirent_read failed: %d\n", ret);
		goto out;
	}

	sle = strlen(nameptr);
	strncpy(dent->d_name, nameptr, sle);
	dent->len = sle;
	free(nameptr, M_TEMP);

out:
	printf("fake_buf.offset :%d %hu\n",msg_buf.offset,sle);
	return msg_buf.offset;
}
