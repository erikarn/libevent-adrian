/*
 * This implements a basic logging API for use by various
 * modules.
 *
 * The design is to be thread-safe and be backend-agnostic -
 * ie, the caller doesn't have to care about the kind of logging
 * going on, just that it's a line based log. It could be to a file,
 * or syslog, or a ring buffer, etc.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <string.h>
#include <err.h>
#include <stdarg.h>
#include <sys/time.h>

#include "logging.h"

void
logfile_init(struct logfile *lf)
{
	pthread_mutex_init(&lf->log_lock, NULL);
	lf->p.fp = NULL;
	lf->p.path = NULL;
	lf->p.buf = calloc(LOGGING_BUFLEN, sizeof(char));
	if (lf->p.buf == NULL)
		err(1, "malloc");
	lf->label = strdup("<unset>");
}

void
logfile_destroy(struct logfile *lf)
{
	logfile_close(lf);
	if (lf->p.path)
		free(lf->p.path);
	lf->p.path = NULL;
	if (lf->label)
		free(lf->label);
	lf->label = NULL;
	if (lf->p.buf)
		free(lf->p.buf);
	lf->p.buf = NULL;
	pthread_mutex_destroy(&lf->log_lock);
}

void
logfile_open(struct logfile *lf, const char *path)
{
	pthread_mutex_lock(&lf->log_lock);
	if (lf->p.fp != NULL)
		logfile_close(lf);
	if (lf->p.path != NULL) {
		free(lf->p.path);
		lf->p.path = NULL;
	}
	lf->p.path = strdup(path);
	lf->p.fp = fopen(lf->p.path, "w+");
	/* XXX error handling? */
	pthread_mutex_unlock(&lf->log_lock);
}

void
logfile_close(struct logfile *lf)
{
	pthread_mutex_lock(&lf->log_lock);
	fclose(lf->p.fp);
	lf->p.fp = NULL;
	pthread_mutex_unlock(&lf->log_lock);
}

/*
 * XXX This will block all writers of this until the fflush()
 * XXX returns, which is not likely what we want.
 */
void
logfile_flush(struct logfile *lf)
{
	pthread_mutex_lock(&lf->log_lock);
	fflush(lf->p.fp);
	pthread_mutex_unlock(&lf->log_lock);
}

/*
 * XXX TODO: add timestamp
 */
void
logfile_printf(struct logfile *lf, const char *fmt, ...)
{
	va_list args;
	struct timeval tv;
	char buf[64];

	va_start(args, fmt);
	(void) gettimeofday(&tv, NULL);

	pthread_mutex_lock(&lf->log_lock);
	if (lf->p.fp != NULL) {
		/* Prepend time if required */
		snprintf(buf, 64, "%ld.%.3ld |",
		    (long int) tv.tv_sec,
		    (long int) tv.tv_usec);
		fprintf(lf->p.fp, "%s", lf->p.buf);
		fflush(lf->p.fp);

		/* Add the logging line */
		vfprintf(lf->p.fp, fmt, args);
	}
	pthread_mutex_unlock(&lf->log_lock);
	va_end(args);
}

void
logfile_vprintf(struct logfile *lf, const char *fmt, va_list args)
{
	struct timeval tv;
	char buf[64];

	(void) gettimeofday(&tv, NULL);

	pthread_mutex_lock(&lf->log_lock);
	if (lf->p.fp != NULL) {
		/* Prepend time if required */
		snprintf(buf, 64, "%ld.%.3ld |",
		    (long int) tv.tv_sec,
		    (long int) tv.tv_usec);
		fprintf(lf->p.fp, "%s", lf->p.buf);
		fflush(lf->p.fp);

		/* Add the logging line */
		vfprintf(lf->p.fp, fmt, args);
	}
	pthread_mutex_unlock(&lf->log_lock);
}
