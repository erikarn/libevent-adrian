#ifndef	__LUSCA_REQUEST_H__
#define	__LUSCA_REQUEST_H__

struct request_holder {
	struct evkeyvalq *headers;
	int response_code;
	char *response_line;
	struct evbuffer *buffer;
};

struct proxy_request {
	TAILQ_ENTRY(proxy_request) (next);
	struct evhttp_request *req;
	struct evhttp_connection *evcon;
	struct request_holder *holder;
	u_short port;
	char *uri;
	int first_chunk;
	uint64_t xid;
};

#endif	/* __LUSCA_REQUEST_H__ */
