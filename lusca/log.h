#ifndef	__LUSCA_LOG_H__
#define	__LUSCA_LOG_H__

/* simple debugging help */
extern int debug;
#define	DNFPRINTF(x, y)		if (debug >= x) fprintf y;

extern struct logfile debug_log;
#define DEBUG(x, fmt, ...) if (debug >= x) debug_printf(&debug_log, fmt, ...)

extern	void debug_printf(struct logfile *lf, const char *fmt, ...);

#endif /* __LUSCA_LOG_H__ */
