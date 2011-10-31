/*
 * This set of routines is designed to log access transactions.
 * This includes front-end, back-end and cache decision entries.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <sys/tree.h>

#include "lusca_request.h"
#include "logging.h"
#include "access_log.h"

extern struct logfile access_log;

void
access_log_write(struct proxy_request *pr,
    const char *who,
    const char *what,
    const char *fmt, ...)
{
	va_list args;
	char buf[8192];	/* XXX */

	va_start(args, fmt);
	vsnprintf(buf, 8192, fmt, args);
	va_end(args);

	logfile_printf(&access_log, "(XID %lld) [%s] %s: %s",
	    pr == NULL ? -1 : (long long int) pr->xid, who, what, buf);
}
