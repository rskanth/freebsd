/*
 * net/protocol.h
 *
 * 9P Protocol Support Code
 */

int p9_buf_vwritef(struct p9_buffer *buf, int proto_version, const char *fmt,
								va_list ap);
int p9_buf_readf(struct p9_buffer *buf, int proto_version, const char *fmt, ...);
int p9_buf_prepare(struct p9_buffer *buf, int8_t type);
int p9_buf_finalize(struct p9_client *clnt, struct p9_buffer *buf);
void p9_buf_reset(struct p9_buffer *buf);
size_t buf_read(struct p9_buffer *buf, void *data, size_t size);
