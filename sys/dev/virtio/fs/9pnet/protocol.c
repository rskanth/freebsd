/*
 * net/protocol.c
 *
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
p9pdu_writef(struct p9_buffer *pdu, int proto_version, const char *fmt, ...);
void p9stat_p9_free(struct p9_wstat *stbuf);

/*static void dump_pdu(struct p9_buffer *pdu)
{
	printf("size %u id %c tag%u\n",pdu->size,pdu->id,pdu->tag);
	printf("strng%s",&pdu->sdata[0]);
	printf("\n");
}*/

void p9stat_p9_free(struct p9_wstat *stbuf)
{
	free(stbuf->name, M_TEMP);
	free(stbuf->uid, M_TEMP);
	free(stbuf->gid, M_TEMP);
	free(stbuf->muid, M_TEMP);
	free(stbuf->extension, M_TEMP);
}

size_t pdu_read(struct p9_buffer *pdu, void *data, size_t size)
{
	size_t len = min(pdu->size - pdu->offset, size);
	//printf("%d %d %d %d sdata %p \n", len, pdu->offset,size,pdu->size ,&pdu->sdata[0]);
	//printf("data in the pdu :%hhu %hhu %hhu %hhu \n",pdu->sdata[0],pdu->sdata[1],pdu->sdata[2],pdu->sdata[3]);
	memcpy(data, &pdu->sdata[pdu->offset], len);
	pdu->offset += len;
	return size - len;
}

static size_t pdu_write(struct p9_buffer *pdu, const void *data, size_t size)
{
	size_t len = min(pdu->capacity - pdu->size, size);
	memcpy(&pdu->sdata[pdu->size], data, len);
	pdu->size += len;
	return size - len;
}


/*
	b - int8_t
	w - int16_t
	d - int32_t
	q - int64_t
	s - string
	u - numeric uid
	g - numeric gid
	S - stat
	Q - qid
	D - data blob (int32_t size followed by void *, results are not p9_freed)
	T - array of strings (int16_t count, followed by strings)
	R - array of qids (int16_t count, followed by qids)
	A - stat for 9p2000.L (p9_stat_dotl)
	? - if optional = 1, continue parsing
*/

static int
p9pdu_vreadf(struct p9_buffer *pdu, int proto_version, const char *fmt,
	va_list ap)
{
	const char *ptr;
	int errcode = 0;

	for (ptr = fmt; *ptr; ptr++) {
		switch (*ptr) {
		case 'b':{
				int8_t *val = va_arg(ap, int8_t *);
				if (pdu_read(pdu, val, sizeof(*val))) {
					errcode = -EFAULT;
					break;
				}
			}
			break;
		case 'w':{
				int16_t *val = va_arg(ap, int16_t *);
				int16_t le_val;
				if (pdu_read(pdu, &le_val, sizeof(le_val))) {
					errcode = -EFAULT;
					break;
				}
				*val = le_val;
			}
			break;
		case 'd':{
				int32_t *val = va_arg(ap, int32_t *);
				int32_t le_val;
				if (pdu_read(pdu, &le_val, sizeof(le_val))) {
					//printf("DId this break \n");
					errcode = -EFAULT;
					break;
				}
				*val = le_val;
				//printf("After sending :%d %d\n",*val,le_val);
		
			}
			break;
		case 'q':{
				int64_t *val = va_arg(ap, int64_t *);
				int64_t le_val;
				if (pdu_read(pdu, &le_val, sizeof(le_val))) {
					errcode = -EFAULT;
					break;
				}
				*val = le_val;
			}
			break;
		case 's':{
				char **sptr = va_arg(ap, char **);
				uint16_t len;

				errcode = p9pdu_readf(pdu, proto_version,
								"w", &len);
				//printf("len should be :%hu \n",len);

				if (errcode)
					break;

				*sptr = malloc(len + 1, M_TEMP, M_NOWAIT);
				if (*sptr == NULL) {
					//printf("code break at EFAULT ..\n");
					errcode = -EFAULT;
					break;
				}
				if (pdu_read(pdu, *sptr, len)) {
					errcode = -EFAULT;
					free(*sptr, M_TEMP);
					*sptr = NULL;
				} else
					(*sptr)[len] = 0;
			}
			break;
		case 'Q':{
				struct p9_qid *qid =
				    va_arg(ap, struct p9_qid *);

				errcode = p9pdu_readf(pdu, proto_version, "bdq",
						      &qid->type, &qid->version,
						      &qid->path);
				printf("done with legit Q read ..\n");
			}
			break;
		case 'S':{
				struct p9_wstat *stbuf =
				    va_arg(ap, struct p9_wstat *);

				memset(stbuf, 0, sizeof(struct p9_wstat));
				stbuf->n_uid = stbuf->n_muid = 0;
				stbuf->n_gid = 0;

				errcode =
				    p9pdu_readf(pdu, proto_version,
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
				if (errcode)
					p9stat_p9_free(stbuf);
				printf("length of file :%lu\n",stbuf->length);  
			}
			break;
		case 'D':{
				uint32_t *count = va_arg(ap, uint32_t *);
				void **data = va_arg(ap, void **);

				errcode =
				    p9pdu_readf(pdu, proto_version, "d", count);
				if (!errcode) {
					*count = MIN(*count,
						  pdu->size - pdu->offset);
					*data = &pdu->sdata[pdu->offset];
				}
			}
			break;
		case 'T':{
				uint16_t *nwname = va_arg(ap, uint16_t *);
				char ***wnames = va_arg(ap, char ***);

				errcode = p9pdu_readf(pdu, proto_version,
								"w", nwname);
				if (!errcode) {
					*wnames = malloc(sizeof(char *) * *nwname, M_TEMP, M_NOWAIT);
					if (!*wnames)
						errcode = -ENOMEM;
				}

				if (!errcode) {
					int i;

					for (i = 0; i < *nwname; i++) {
						errcode =
						    p9pdu_readf(pdu,
								proto_version,
								"s",
								&(*wnames)[i]);
						if (errcode)
							break;
					}
				}

				if (errcode) {
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

				errcode =
				    p9pdu_readf(pdu, proto_version, "w", nwqid);
				if (!errcode) {
					*wqids =
					    malloc(*nwqid *
						    sizeof(struct p9_qid), M_TEMP, M_NOWAIT);
					if (*wqids == NULL)
						errcode = -ENOMEM;
				}

				if (!errcode) {
					int i;

					for (i = 0; i < *nwqid; i++) {
						errcode =
						    p9pdu_readf(pdu,
								proto_version,
								"Q",
								&(*wqids)[i]);
						if (errcode)
							break;
					}
				}

				if (errcode) {
					free(*wqids, M_TEMP);
					*wqids = NULL;
				}
			}
			break;
		case 'A': {
				struct p9_stat_dotl *stbuf =
				    va_arg(ap, struct p9_stat_dotl *);

				memset(stbuf, 0, sizeof(struct p9_stat_dotl));
				errcode =
				    p9pdu_readf(pdu, proto_version,
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

		if (errcode)
			break;
	}

	return errcode;
}

int
p9pdu_vwritef(struct p9_buffer *pdu, int proto_version, const char *fmt,
	va_list ap)
{
	const char *ptr;
	int errcode = 0;

	for (ptr = fmt; *ptr; ptr++) {
		switch (*ptr) {
		case 'b':{
				int8_t val = va_arg(ap, int);
				if (pdu_write(pdu, &val, sizeof(val)))
					errcode = -EFAULT;
				printf("DId b %u \n",val);
				printf("size %u id %c tag%u\n",pdu->size,pdu->id,pdu->tag);
				printf("bit mapint values%hhu \n",pdu->sdata[4]);
	
			}
			break;
		case 'w':{
				int16_t val = va_arg(ap, int);
				if (pdu_write(pdu, &val, sizeof(val)))
					errcode = -EFAULT;
			}
			break;
		case 'd':{
				int32_t val = va_arg(ap, int32_t);
				printf("before conversion :%d %d\n",val,pdu->size);
				if (pdu_write(pdu, &val, sizeof(val)))
					errcode = -EFAULT;
					printf("DId  %d\n",val);
					printf("size %u id %c tag%u\n",pdu->size,pdu->id,pdu->tag);
					printf("int values%d %d \n",pdu->sdata[0],pdu->sdata[5]);
				
			}
			break;
		case 'q':{
				int64_t val = va_arg(ap, int64_t);
				if (pdu_write(pdu, &val, sizeof(val)))
					errcode = -EFAULT;
			}
			break;
		case 's':{
				const char *sptr = va_arg(ap, const char *);
				uint16_t len = 0;
				if (sptr)
					len = MIN(strlen(sptr), 16);

				errcode = p9pdu_writef(pdu, proto_version,
								"w", len);
				printf("DId %s \n",sptr);
				printf("size %u id %c tag%u\n",pdu->size,pdu->id,pdu->tag);

				if (!errcode && pdu_write(pdu, sptr, len))
					errcode = -EFAULT;

				printf("strng %hhu %hhu %s  \n",pdu->sdata[9],pdu->sdata[10],&pdu->sdata[11]);
			}
			break;
		case 'Q':{
				const struct p9_qid *qid =
				    va_arg(ap, const struct p9_qid *);
				errcode =
				    p9pdu_writef(pdu, proto_version, "bdq",
						 qid->type, qid->version,
						 qid->path);
			} break;
		case 'S':{
				const struct p9_wstat *stbuf =
				    va_arg(ap, const struct p9_wstat *);
				errcode =
				    p9pdu_writef(pdu, proto_version,
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
		case 'T':{
				uint16_t nwname = va_arg(ap, int);
				const char **wnames = va_arg(ap, const char **);

				errcode = p9pdu_writef(pdu, proto_version, "w",
									nwname);
				if (!errcode) {
					int i;

					for (i = 0; i < nwname; i++) {
						errcode =
						    p9pdu_writef(pdu,
								proto_version,
								 "s",
								 wnames[i]);
						if (errcode)
							break;
					}
				}
			}
			break;
		case 'R':{
				uint16_t nwqid = va_arg(ap, int);
				struct p9_qid *wqids =
				    va_arg(ap, struct p9_qid *);

				errcode = p9pdu_writef(pdu, proto_version, "w",
									nwqid);
				if (!errcode) {
					int i;

					for (i = 0; i < nwqid; i++) {
						errcode =
						    p9pdu_writef(pdu,
								proto_version,
								 "Q",
								 &wqids[i]);
						if (errcode)
							break;
					}
				}
			}
			break;
		case 'I':{
				struct p9_iattr_dotl *p9attr = va_arg(ap,
							struct p9_iattr_dotl *);

				errcode = p9pdu_writef(pdu, proto_version,
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

		if (errcode)
			break;
	}

	return errcode;
}

int p9pdu_readf(struct p9_buffer *pdu, int proto_version, const char *fmt, ...)
{
	va_list ap;
	int ret;

	va_start(ap, fmt);
	ret = p9pdu_vreadf(pdu, proto_version, fmt, ap);
	va_end(ap);

	return ret;
}

static int
p9pdu_writef(struct p9_buffer *pdu, int proto_version, const char *fmt, ...)
{
	va_list ap;
	int ret;

	va_start(ap, fmt);
	ret = p9pdu_vwritef(pdu, proto_version, fmt, ap);
	va_end(ap);

	return ret;
}

int p9stat_read(struct p9_client *clnt, char *buf, size_t len, struct p9_wstat *st)
{
	struct p9_buffer fake_pdu;
	int ret;

	fake_pdu.size = len;
	fake_pdu.capacity = len;
	fake_pdu.sdata = buf;
	fake_pdu.offset = 0;

	ret = p9pdu_readf(&fake_pdu, clnt->proto_version, "S", st);
	if (ret) {
		p9_debug(PROTO, "<<< p9stat_read failed: %d\n", ret);
	}

	return ret;
}

int p9pdu_prepare(struct p9_buffer *pdu, int8_t type)
{
	int tag = 0;
	pdu->id = type;
	printf("p9pdu_prepare ID%d \n",pdu->id);

	return p9pdu_writef(pdu, 0, "dbw", 0, type, tag);
}

int p9pdu_finalize(struct p9_client *clnt, struct p9_buffer *pdu)
{
	int size = pdu->size;
	int err;

	pdu->size = 0;
	err = p9pdu_writef(pdu, 0, "d", size);
	pdu->size = size;

	p9_debug(PROTO, ">>> size=%d type: %d tag: %d\n",
		 pdu->size, pdu->id, pdu->tag);

	return err;
}

void p9pdu_reset(struct p9_buffer *pdu)
{
	pdu->offset = 0;
	pdu->size = 0;
}

/* Directory entry read with the buf we have. Call this once we have the 
 * buf to parse .*/
int p9dirent_read(struct p9_client *clnt, char *buf, int start, int len,
		  struct dirent *dirent)
{
	struct p9_buffer fake_pdu;
	int ret;
	char *nameptr;
	struct p9_qid qid;
	uint16_t le;
	uint64_t d_off; // NOt used yet/

	fake_pdu.size = len;
	fake_pdu.capacity = len;
	fake_pdu.sdata = buf;
	fake_pdu.offset = start;

	ret = p9pdu_readf(&fake_pdu, clnt->proto_version, "Qqbs", &qid,
			  &d_off, &dirent->d_type, &nameptr);
	if (ret) {
		p9_debug(PROTO, "<<< p9dirent_read failed: %d\n", ret);
		goto out;
	}

	le = strlen(nameptr);
	strncpy(dirent->d_name, nameptr, le);
 	dirent->d_namlen = le;
	free(nameptr, M_TEMP);
	dirent->d_fileno = (uint32_t)(qid.path >> 32);

out:
	printf("fake_pdu.offset :%d %hu\n",fake_pdu.offset,le);
	return fake_pdu.offset;
}
