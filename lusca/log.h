#ifndef	__LUSCA_LOG_H__
#define	__LUSCA_LOG_H__

/* simple debugging help */
extern int debug;
#define DNFPRINTF(x, y) if (debug >= x) fprintf y;

#endif /* __LUSCA_LOG_H__ */
