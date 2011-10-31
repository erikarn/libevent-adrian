#ifndef	__LUSCA_DNS_H__
#define	__LUSCA_DNS_H__

struct dns_request {
	struct dns_cache *entry;
	TAILQ_ENTRY(dns_request) (next);
	void *arg;
	void (*cb)(struct dns_request *r, void *arg);
};

struct dns_cache {
	SPLAY_ENTRY(dns_cache) node;
	pthread_mutex_t entry_lock;
	char *name;
	TAILQ_HEAD(requestqueue, dns_request) entries;
	struct in_addr *addresses;
	int address_count;
	struct event ev_timeout;
};

extern struct dns_cache * dns_new(const char *name);
extern void dns_free(struct dns_cache *entry);
extern void dns_init(struct event_base *base);
extern void dns_lock(void);
extern void dns_unlock(void);

extern void dns_entry_lock(struct dns_cache *entry);
extern void dns_entry_unlock(struct dns_cache *entry);

extern struct evdns_base *dns_base;

#endif	/* __LUSCA_DNS_H__ */
