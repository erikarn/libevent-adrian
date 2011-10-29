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
#include "lusca.h"

/* tell our callers that the name could not be resolved */
static struct request_holder *request_holder_new(struct evhttp_request *req);
static void request_holder_free(struct request_holder *rh);
static void http_send_reply(const char *result, void *arg);
static void http_set_response_headers(struct proxy_request *pr);
static int http_request_first_chunk(struct evhttp_request *req, void *arg);
static void inform_domain_notfound(struct evhttp_request *request);
static void inform_no_referer(struct evhttp_request *request);

int debug = 0;

int behave_as_proxy = 1;

/* XXX ew, global */
struct event_base *ev_base = NULL;

/*
 * Called when an upstream connection has read a chunk.
 */
static void
http_server_chunk_cb(struct evhttp_request *req, void *arg)
{
	struct evbuffer *eb;
	struct proxy_request *pr = arg;

	DNFPRINTF(10, (stderr, "%s: req=%p, pr=%p\n", __func__, req, pr));

	if (pr->first_chunk == 0)
		if (http_request_first_chunk(req, pr) == 0)
			return;

	eb = evhttp_request_get_input_buffer(req);
	evhttp_send_reply_chunk(pr->req, eb);
}

static void
http_copy_headers(struct evkeyvalq *dst, struct evkeyvalq *src)
{
	struct evkeyval *kv;
	TAILQ_FOREACH(kv, src, next) {
		/* we cannot inject javascript into an encoded data stream */
		if (strcasecmp(kv->key, "Transfer-Encoding") == 0 ||
		    strcasecmp(kv->key, "Accept-Encoding") == 0 ||
		    strcasecmp(kv->key, "Connection") == 0 ||
		    strcasecmp(kv->key, "Keep-Alive") == 0 ||
		    strcasecmp(kv->key, "Proxy-Connection") == 0) {
			DNFPRINTF(2, (stderr, "[HEADER] Ignoring %s: %s\n",
				kv->key, kv->value));
			continue;
		}
		/* we might want to do some filtering here */
		DNFPRINTF(2, (stderr, "[DEBUG] Header %s: %s\n",
			kv->key, kv->value));
		evhttp_add_header(dst, kv->key, kv->value);
	}
}

static void
map_location_header(struct evhttp_request *req, const char *location)
{
	static char path[1024];
	char *host, *uri;
	u_short port;
			
	if (http_hostportfile(location, NULL, NULL, NULL) == -1) {
		if (http_hostportfile(req->uri, &host, &port, &uri) == -1)
			return;
		if (location[0] == '/') {
			snprintf(path, sizeof(path), "http://%s%s",
			    host, location);
		} else {
			snprintf(path, sizeof(path), "http://%s%s%s",
			    host, uri, location);
		}
	} else {
		strlcpy(path, location, sizeof(path));
	}
	fprintf(stderr, "[MAP] %s -> %s\n", path, req->uri);
}

static void
inform_domain_notfound(struct evhttp_request *request)
{
	struct evbuffer *databuf = evbuffer_new();
	char *escaped = evhttp_htmlescape(request->uri);
	assert(databuf != NULL);

	evbuffer_add_printf(databuf,
	    "<html><head><title>Domain not found</title></head>"
	    "<body><h1>Domain not found</h1>\n"
	    "Cannot find an IP address for %s</body></html>",
	    escaped);
	free(escaped);

	/* we cannot allow this request */
	evhttp_send_reply(request,
	    HTTP_BADREQUEST, "Disallowing dangerous request.",
	    databuf);
	evbuffer_free(databuf);
}

static void
inform_error(struct evhttp_request *request,
    int error_code, const char *error_text)
{
	struct evbuffer *databuf = evbuffer_new();
	const char *error_title = "Unknown Error";
	const char *error_add_text = "";
	assert(databuf != NULL);

	switch (error_code) {
	case HTTP_SERVUNAVAIL:
		error_title = "Internal Service Error";
		error_add_text = error_text;
		break;
	case HTTP_BADREQUEST:
		error_title = "Invalid Request";
		error_add_text =
		    "The proxy received a request that contained invalid or "
		    "badly formatted HTTP, or a request for a private IP "
		    "address that has been forbidden by configuration.";
		break;
	case HTTP_NOTFOUND:
		error_title = "Document Not Found";
		error_add_text =
		    "The document could not be found at the specified "
		    "location.";
		break;
	}

	evbuffer_add_printf(databuf,
	    "<html><head><title>%s</title></head>"
	    "<body><div style=\"border: solid 1px; padding: 2px; "
	    "width: 60%%; "
	    "background-color: #dcdcee; font-family: Verdana, Arial;\">"
	    "<h2>%s</h2>\n"
	    "Could not complete request to <b>http://%s/</b>."
	    "%s"
	    "<p>"
	    "You are using Lusca 2.0-alpha %s."
	    "</div>"
	    "</body></html>",
	    error_title, error_title,
	    evhttp_find_header(request->input_headers, "Host"),
	    error_add_text, VERSION);

	/* we cannot allow this request */
	evhttp_send_reply(request, error_code, error_text, databuf);
	evbuffer_free(databuf);
}

static void
inform_no_referer(struct evhttp_request *request)
{
	struct evbuffer *databuf = evbuffer_new();
	char *escaped = evhttp_encode_uri(request->uri);
	char *html_escaped = evhttp_htmlescape(request->uri);
	assert(databuf != NULL);

	evbuffer_add_printf(databuf,
	    "<html><head><title>Request Denied</title></head>"
	    "<body><div style=\"border: solid 1px; padding: 2px; "
	    "width: 40%%; "
	    "background-color: #dcdcee; font-family: Verdana, Arial;\">"
	    "<h2>Request Denied</h2>\n"
	    "</body></html>");
	free(escaped);
	free(html_escaped);

	/* we cannot allow this request */
	evhttp_send_reply(request, HTTP_NOTFOUND, "Not Found", databuf);
	evbuffer_free(databuf);
}

/*
 * This is called when the upstream connection has completed.
 *
 * Since we're using the streaming API, this will be called
 * after the last chunked reply body callback is done.
 *
 * If the reply is empty, then req shouldn't be NULL and
 * thus we'll just get an empty reply.
 */
static void
http_request_complete(struct evhttp_request *req, void *arg)
{
	struct proxy_request *pr = arg;

	DNFPRINTF(10, (stderr, "%s: pr=%p\n", __func__, pr));

	if (req == NULL || req->response_code == 0) {
		/* potential request timeout; unreachable machine, etc. */
		pr->holder = NULL;
		http_send_reply("error", pr);
		proxy_request_free(pr);
		return;
	}

	/*
	 * Send response headers if the response is empty!
	 */
	if (pr->first_chunk == 0)
		http_request_first_chunk(req, pr);

	evhttp_send_reply_end(pr->req);

	/* We're now done, so free the connection side */
	proxy_request_free(pr);
}

static int
http_request_first_chunk(struct evhttp_request *req, void *arg)
{
	struct proxy_request *pr = arg;

	DNFPRINTF(10, (stderr, "%s: pr=%p, first_chunked=%d\n", __func__, pr,
	    pr->first_chunk));
	if (pr->first_chunk == 1)
		return 1;		/* We can continue */

	pr->first_chunk = 1;

	if (req == NULL || req->response_code == 0) {
		/* potential request timeout; unreachable machine, etc. */
		pr->holder = NULL;
		http_send_reply("error", pr);
		proxy_request_free(pr);
		return 0;
	}
	pr->holder = request_holder_new(req);
	/* Setup the headers to send */
	http_set_response_headers(pr);
	evhttp_send_reply_start(pr->req, pr->holder->response_code,
	    pr->holder->response_line);
	return 1;
}

static void
http_add_uncache_headers(struct evhttp_request *request)
{
	/* make everything we do no-cacheable */
	evhttp_remove_header(request->output_headers, "Pragma");
	evhttp_add_header(request->output_headers,
	    "Pragma", "no-cache, no-store");

	evhttp_remove_header(request->output_headers, "Cache-Control");
	evhttp_add_header(request->output_headers,
	    "Cache-Control",
	    "no-cache, no-store, must-revalidate, max-age=-1");
}

/*
 * Send a whole reply. Caller must free the proxy_request struct.
 */
static void
http_send_reply(const char *result, void *arg)
{
	struct proxy_request *pr = arg;
	struct request_holder *rh = pr->holder;

	DNFPRINTF(10, (stderr, "%s: pr=%p\n", __func__, pr));

	/* Setup response headers */
	http_set_response_headers(pr);

	/* Send the whole reply */
	evhttp_send_reply(pr->req, rh->response_code, rh->response_line,
	    rh->buffer);
}

static void
http_set_response_headers(struct proxy_request *pr)
{
	struct request_holder *rh = pr->holder;
	const char *location = NULL;
	const char *content_type = NULL;
	int ishtml = 0;

	DNFPRINTF(10, (stderr, "%s: pr=%p\n", __func__, pr));

#if 0
	log_request(LOG_INFO, pr->req, site);
#endif

	if (rh == NULL) {
		/* we have nothing to serve */
		inform_error(pr->req, HTTP_SERVUNAVAIL,
		    "Could not reach remote location.");
		proxy_request_free(pr);
		return;
	}

	location = evhttp_find_header(rh->headers, "Location");
	/* keep track of the redirect so that we can tie it together */
	if (location != NULL)
		map_location_header(pr->req, location);

	http_copy_headers(pr->req->output_headers, rh->headers);

	/*
	 * if not running as proxy or if we inject control js into HTML,
	 * we need to make the resulting response uncachable, otherwise
	 * we face situations where the js gets executed without SpyBye
	 * having the corresponding state.
	 */
	content_type = evhttp_find_header(rh->headers, "Content-Type");
	ishtml = content_type != NULL &&
	    strncasecmp(content_type, "text/html", 9) == 0;
	if (!behave_as_proxy || ishtml) {
		/*
		 * make everything we do uncacheable, so that we
		 * always get all requests 
		 */
		http_add_uncache_headers(pr->req);
	}

#if 0
	/* inject our control code here */
	if (!use_iframes && ishtml) {
		inject_control_javascript(rh->buffer);
		/* fix up the content length */
		evhttp_remove_header(pr->req->output_headers,
		    "Content-Length");
	}
#endif
}

static void
dispatch_single_request(struct dns_cache *dns, struct proxy_request *pr)
{
	struct evhttp_request *request;
	char *address = inet_ntoa(dns->addresses[0]);
	const char *host = NULL;

	DNFPRINTF(10, (stderr, "%s: pr=%p\n", __func__, pr));

	assert(pr->evcon == NULL);
	/* XXX dns_base! */
	pr->evcon = evhttp_connection_base_new(ev_base, dns_base,
	    address, pr->port);
	fprintf(stderr, "[NET] Connecting %s:%d\n", address, pr->port);
	if (pr->evcon == NULL)
		goto fail;

	evhttp_connection_set_timeout(pr->evcon, SPYBYE_CONNECTION_TIMEOUT);

	/* we got the connection now - queue the request */
	request = evhttp_request_new(http_request_complete, pr);
	if (request == NULL)
		goto fail;

	/* Copy over the relevant headers from the request */
	http_copy_headers(request->output_headers, pr->req->input_headers);

	/*
	 * The request may not have a Host header but has a complete
	 * request URL. If it doesn't, add it.
	 */
	host = evhttp_request_get_host(pr->req);
	if (host != NULL) {
		evhttp_remove_header(request->output_headers,
		    "Host");
		evhttp_add_header(request->output_headers, "Host", host);
	}

	evhttp_add_header(request->output_headers,
	    "X-Forwarded-For", pr->req->remote_host);

	/* for post requests, we might have to add the buffer */
	/* XXX what about other request types w/ request bodies? */
	if (pr->req->type == EVHTTP_REQ_POST)
		evbuffer_add_buffer(request->output_buffer,
		    pr->req->output_buffer);

	evhttp_add_header(request->output_headers, "Connection", "close");
	/* We want the reply data chunked */
	evhttp_request_set_chunked_cb(request, http_server_chunk_cb);
	evhttp_make_request(pr->evcon, request, pr->req->type, pr->uri);
	return;

fail:
	inform_error(pr->req, HTTP_SERVUNAVAIL, "Out of resources");
	proxy_request_free(pr);
	return;
}

void
dns_dispatch_requests(struct dns_cache *dns)
{
	struct proxy_request *entry;
	while ((entry = TAILQ_FIRST(&dns->entries)) != NULL) {
		TAILQ_REMOVE(&dns->entries, entry, next);
		
		dispatch_single_request(dns, entry);
	}
}

void
dns_dispatch_error(struct dns_cache *dns_entry)
{
	struct proxy_request *entry;
	while ((entry = TAILQ_FIRST(&dns_entry->entries)) != NULL) {
		TAILQ_REMOVE(&dns_entry->entries, entry, next);

		inform_domain_notfound(entry->req);
		proxy_request_free(entry);
	}

	/* no negative caching */
	dns_free(dns_entry);
}

static void
request_add_dns(struct dns_cache *entry, struct proxy_request *pr)
{
	TAILQ_INSERT_TAIL(&entry->entries, pr, next);

	/* still waiting for resolution */
	if (entry->address_count == 0)
		return;

	dns_dispatch_requests(entry);
}

/*
 * Receive all possible requests - analyze them for doing stuff
 */

void
request_handler(struct evhttp_request *request, void *arg)
{
	char *host, *uri;
	const char *referer;
	u_short port;
	struct dns_cache *entry;
	struct proxy_request *pr;

	if (http_hostportfile(request->uri, &host, &port, &uri) == -1) {
		inform_error(request, HTTP_BADREQUEST, "Illegal request.");
		return;
	}

	/* now insert the request into our status object */
	referer = evhttp_find_header(request->input_headers, "Referer");
	fprintf(stderr, "[URL] Request for %s (%s) from %s\n",
	    request->uri, referer, request->remote_host);
	if (referer == NULL && !behave_as_proxy) {
//		log_request(LOG_INFO, request, NULL);
		inform_no_referer(request);
		return;
	}

#if 0
	/* make sure that we do not send a referer if this is a root URL */
	if (site->parent == NULL)
		evhttp_remove_header(request->input_headers, "Referer");
#endif

	if ((entry = dns_new(host)) == NULL) {
		fprintf(stderr, "[PRIVATE] Attempt to visit private IP: %s\n",
		    request->uri);
//		log_request(LOG_INFO, request, site);
		inform_error(request,
		    HTTP_BADREQUEST, "Access to private IP disallowed.");
		return;
	}
	pr = proxy_request_new(request, port, uri);
	request_add_dns(entry, pr);
}

struct proxy_request *
proxy_request_new(struct evhttp_request *req, u_short port, char *uri)
{
	struct proxy_request *pr;

	if ((pr = calloc(1, sizeof(struct proxy_request))) == NULL)
		err(1, "calloc");

	pr->uri = strdup(uri);
	if (pr->uri == NULL)
		err(1, "strdup");

	pr->req = req;
	pr->port = port;

	return (pr);
}

static void
proxy_request_free_evcon(int fd, short what, void *arg)
{
	struct evhttp_connection *evcon = arg;
	evhttp_connection_free(evcon);
}

void
proxy_request_free(struct proxy_request *pr)
{

	DNFPRINTF(10, (stderr, "%s: pr=%p\n", __func__, pr));

	if (pr->evcon != NULL) {
		struct timeval tv;
		
		timerclear(&tv);
		event_base_once(ev_base, -1, EV_TIMEOUT,
		    proxy_request_free_evcon, pr->evcon, &tv);
	}

	if (pr->holder != NULL) {
		request_holder_free(pr->holder);
	}

	free(pr->uri);
	free(pr);
}

static struct request_holder *
request_holder_new(struct evhttp_request *req)
{
	struct request_holder *rh = calloc(1, sizeof(struct request_holder));
	assert(rh != NULL);
	rh->headers = malloc(sizeof(struct evkeyvalq *));
	assert(rh->headers != NULL);
	TAILQ_INIT(rh->headers);

	http_copy_headers(rh->headers, req->input_headers);

	/* copy all the data that we need to make the reply */
	rh->buffer = evbuffer_new();
	assert(rh->buffer != NULL);
	evbuffer_add(rh->buffer,
	    EVBUFFER_DATA(req->input_buffer),
	    EVBUFFER_LENGTH(req->input_buffer));
	rh->response_code = req->response_code;
	rh->response_line = strdup(req->response_code_line);
	assert(rh->response_line != NULL);

	return (rh);
}

static void
request_holder_free(struct request_holder *rh)
{
	evhttp_clear_headers(rh->headers);
	free(rh->headers);
	free(rh->response_line);
	evbuffer_free(rh->buffer);
	free(rh);
}

void
lusca_init(struct event_base *base)
{
	evtag_init();
	ev_base = base;
}
