#ifndef	__LUSCA_LUSCA_H__
#define	__LUSCA_LUSCA_H__

#define SPYBYE_CONNECTION_TIMEOUT	120

extern	struct proxy_request *proxy_request_new(struct evhttp_request *req,
	    u_short port, char *uri);
extern	void proxy_request_free(struct proxy_request *);

/* These are called by dns.c routines */
extern void dns_dispatch_error(struct dns_cache *);
extern void dns_dispatch_requests(struct dns_cache *dns_entry);

extern void request_handler(struct evhttp_request *request, void *arg);
extern void lusca_init(struct event_base *base);
extern	void lusca_shutdown(void);

#endif	/* __LUSCA_LUSCA_H__ */
