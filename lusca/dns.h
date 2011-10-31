#ifndef	__LUSCA_DNS_H__
#define	__LUSCA_DNS_H__

struct dns_cache {
	SPLAY_ENTRY(dns_cache) node;
	char *name;
	TAILQ_HEAD(requestqueue, proxy_request) entries;
	struct in_addr *addresses;
	int address_count;
	struct event ev_timeout;
};

extern struct dns_cache * dns_new(const char *name);
extern void dns_free(struct dns_cache *entry);
extern void dns_init(struct event_base *base);
extern void dns_lock(void);
extern void dns_unlock(void);

extern struct evdns_base *dns_base;

#endif	/* __LUSCA_DNS_H__ */
