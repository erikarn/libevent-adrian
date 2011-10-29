/*
 * Copyright 2007 Niels Provos <provos@citi.umich.edu>
 * All rights reserved.
 */

#include <sys/types.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/time.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <err.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>

#include <event.h>
#include <event2/event.h>
#include <event2/http.h>
#include <event2/http_struct.h>

#include "utils.h"

extern int debug;

/* Separated host, port and file from URI */

int
http_hostportfile(const char *url, char **phost, u_short *pport, char **pfile)
{
	static int off;
	static char shost[2][1024];
	static char sfile[2][1024];
	char *p;
	const char *p2;
	int len;
	u_short port;

	if (++off > 1) off = 0;

	len = strlen(HTTP_PREFIX);
	if (strncasecmp(url, HTTP_PREFIX, len))
		return (-1);

	url += len;

	/* We might overrun */
	if (strlcpy(shost[off], url, sizeof(shost[off])) >= sizeof(shost[off]))
		return (-1);

	p = strchr(shost[off], '/');
	if (p != NULL) {
		*p = '\0';
		p2 = p + 1;
	} else
		p2 = NULL;

	if (pfile != NULL) {
		/* Generate request file */
		if (p2 == NULL)
			p2 = "";
		snprintf(sfile[off], sizeof(sfile[off]), "/%s", p2);
	}

	p = strchr(shost[off], ':');
	if (p != NULL) {
		*p = '\0';
		port = atoi(p + 1);

		if (port == 0)
			return (-1);
	} else
		port = HTTP_DEFAULTPORT;

	if (phost != NULL)
		*phost = shost[off];
	if (pport != NULL)
		*pport = port;
	if (pfile != NULL)
		*pfile = sfile[off];

	return (0);
}

/* match a url against a pattern */
int
match_url(const char *url, const char *pattern_host, const char *pattern_uri)
{
	char *host, *uri;
	u_short port;

	if (http_hostportfile((char *)url, &host, &port, &uri) == -1)
		return (0);

	if (strlen(pattern_host) > strlen(host))
		return (0);

	if (pattern_uri != NULL && strlen(pattern_uri) > strlen(uri))
		return (0);

	if (strcasecmp(host + strlen(host) - strlen(pattern_host),
		pattern_host))
		return (0);

	if (pattern_uri == NULL)
		return (1);

	return (strncasecmp(uri, pattern_uri, strlen(pattern_uri)) == 0);
}

static const char *private_prefixes[] = {
	"10.",
	"127.",
	"192.168.",
	NULL
};

int
check_private_ip(void *arg, int count)
{
	struct in_addr *address = (struct in_addr *)arg;

	while (count--) {
		char *ip_addr = inet_ntoa(*address++);
		const char **p;

		/* is this even possible? */
		if (ip_addr == NULL)
			return (1);

		for (p = &private_prefixes[0]; *p != NULL; p++) {
			if (strncmp(ip_addr, *p, strlen(*p)) == 0)
				return (1);
		}
	}

	return (0);
}
