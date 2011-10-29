/*
 * Copyright 2007 Niels Provos <provos@citi.umich.edu>
 * All rights reserved.
 */

#ifndef UTILS_H_
#define UTILS_H_

#define USER_AGENT		"SpyBye/"VERSION
#define HTTP_PREFIX		"http://"
#define HTTP_DEFAULTPORT	80
#define HTTP_MAX_URL		2048

int http_hostportfile(const char *url,
    char **phost, u_short *pport, char **pfile);
int match_url(
	const char *url, const char *pattern_host, const char *pattern_uri);

int check_private_ip(void *addresses, int count);

#endif /* UTILS_H_ */
