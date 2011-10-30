#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <string.h>
#include <err.h>
#include <stdarg.h>
#include <sys/time.h>

#include "logging.h"
#include "log.h"

void
debug_printf(const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	logfile_vprintf(&debug_log, fmt, args);
	va_end(args);
}

