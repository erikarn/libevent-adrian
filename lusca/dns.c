/*
 * This is based on spybye/spybye.c, by Niels Provos.
 */

#include <sys/types.h>

#ifdef HAVE_CONFIG_H
#include "../config.h"
#endif

#include <sys/time.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/queue.h>
#include <sys/tree.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <err.h>
#include <unistd.h>
#include <assert.h>
#include <time.h>
#include <syslog.h>
#include <pthread.h>

#include <event.h>
#include <event2/event.h>
#include <event2/http.h>
#include <event2/buffer.h>
#include <event2/util.h>
#include <event2/keyvalq_struct.h>
#include <event2/event_struct.h>

#include <event2/dns.h>
#include <event2/http.h>
#include <event2/http_struct.h>
#include <event2/tag.h>

#include "log.h"
#include "utils.h"
#include "dns.h"
#include "lusca_request.h"
#include "lusca.h"	/* needed for the callback function */
#include "access_log.h"

struct evdns_base *dns_base = NULL;
struct event_base *dns_ev_base = NULL;

static int
dns_compare(struct dns_cache *a, struct dns_cache *b)
{
	return strcasecmp(a->name, b->name);
}

pthread_mutex_t dns_mutex;
static SPLAY_HEAD(dns_tree, dns_cache) root;

SPLAY_PROTOTYPE(dns_tree, dns_cache, node, dns_compare);
SPLAY_GENERATE(dns_tree, dns_cache, node, dns_compare);

void
dns_lock(void)
{
	pthread_mutex_lock(&dns_mutex);
}

void
dns_unlock(void)
{
	pthread_mutex_unlock(&dns_mutex);
}

void
dns_entry_lock(struct dns_cache *entry)
{

	pthread_mutex_lock(&entry->entry_lock);
}

void
dns_entry_unlock(struct dns_cache *entry)
{
	pthread_mutex_unlock(&entry->entry_lock);
}

static void
dns_ttl_expired(int result, short what, void *arg)
{
	struct dns_cache *dns = arg;
	
	access_log_write(NULL, "DNS", "Expire", "Expire entry %s\n", dns->name);

	dns_lock();
	assert(TAILQ_FIRST(&dns->entries) == NULL);
	dns_free(dns);
	dns_unlock();
}

static void
dns_resolv_cb(int result, char type, int count, int ttl,
    void *addresses, void *arg)
{
	struct dns_cache *entry = arg;
	struct timeval tv;

	access_log_write(NULL, "DNS", "Response", "%s: result code = %d\n",
	    entry->name, result);

	entry->status = result;

	if (result != DNS_ERR_NONE) {
		/* we were not able to resolve the name */
		dns_dispatch_requests(entry);

		/* no negative caching */
		dns_lock();
		dns_free(entry);
		dns_unlock();
		return;
	}

	/* copy the addresses */
	entry->addresses = calloc(count, sizeof(struct in_addr));
	if (entry->addresses == NULL)
		err(1, "calloc");
	entry->address_count = count;
	memcpy(entry->addresses, addresses, count * sizeof(struct in_addr));

	/* Dispatch requests waiting for the given entry */
	dns_dispatch_requests(entry);

	/* expire it after its time-to-live is over */
	evtimer_set(&entry->ev_timeout, dns_ttl_expired, entry);
	event_base_set(dns_ev_base, &entry->ev_timeout);
	timerclear(&tv);
	tv.tv_sec = ttl;
	evtimer_add(&entry->ev_timeout, &tv);
}

struct dns_cache *
dns_new(const char *name)
{
	struct dns_cache *entry, tmp;
	struct in_addr address;

	tmp.name = (char *)name;
	dns_lock();
	if ((entry = SPLAY_FIND(dns_tree, &root, &tmp)) != NULL) {
		dns_unlock();
		return (entry);
	}
	dns_unlock();

	entry = calloc(1, sizeof(struct dns_cache));
	if (entry == NULL)
		err(1, "calloc");

	entry->name = strdup(name);
	pthread_mutex_init(&entry->entry_lock, NULL);
	if (entry->name == NULL)
		err(1, "strdup");

	TAILQ_INIT(&entry->entries);

	dns_lock();
	SPLAY_INSERT(dns_tree, &root, entry);
	dns_unlock();

	if (inet_aton(entry->name, &address) != 1) {
		access_log_write(NULL, "DNS", "Request",
		    "Resolving IPv4 for %s\n", entry->name);
		evdns_base_resolve_ipv4(dns_base, entry->name, 0,
		    dns_resolv_cb, entry);
	} else {
		/* we already have an address - no dns necessary */
		dns_resolv_cb(DNS_ERR_NONE, DNS_IPv4_A,
		    1, 3600, &address, entry);
	}

	return (entry);
}

void
dns_free(struct dns_cache *entry)
{
	SPLAY_REMOVE(dns_tree, &root, entry);
	pthread_mutex_destroy(&entry->entry_lock);
	free(entry->addresses);
	free(entry->name);
	free(entry);
}

void
dns_init(struct event_base *base)
{
	SPLAY_INIT(&root);
	pthread_mutex_init(&dns_mutex, NULL);
	dns_base = evdns_base_new(base, 1);
	dns_ev_base = base;
	if (dns_base == NULL) {
		fprintf(stderr, "%s: evdns_base_new() failed!\n", __func__);
		exit(1);
	}
}
