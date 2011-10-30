#ifndef	__LUSCA_LOG_H__
#define	__LUSCA_LOG_H__

/* simple debugging help */
extern int debug;

extern struct logfile debug_log;
#define DEBUG(x, y) if (debug >= y) debug_printf

extern	void debug_printf(const char *fmt, ...);

#endif /* __LUSCA_LOG_H__ */
