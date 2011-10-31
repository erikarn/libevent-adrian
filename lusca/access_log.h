#ifndef	__LUSCA_ACCESS_LOG_H__
#define	__LUSCA_ACCESS_LOG_H__

extern	void access_log_write(struct proxy_request *pr, const char *who,
	    const char *what,
	    const char *fmt, ...);

#endif	/* __LUSCA_ACCESS_LOG_H__ */
