#ifndef	__LUSCA_LUSCA_H__
#define	__LUSCA_LUSCA_H__

#define SPYBYE_CONNECTION_TIMEOUT	120

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
};

struct proxy_request *proxy_request_new(
	struct evhttp_request *req, u_short port, char *uri);
void proxy_request_free(struct proxy_request *);

/* These are called by dns.c routines */
extern void dns_dispatch_error(struct dns_cache *);
extern void dns_dispatch_requests(struct dns_cache *dns_entry);

extern void request_handler(struct evhttp_request *request, void *arg);
extern void lusca_init(struct event_base *base);

#endif	/* __LUSCA_LUSCA_H__ */
