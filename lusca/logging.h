#ifndef	__LUSCA_LOGGING_H__
#define	__LUSCA_LOGGING_H__

#define	LOGGING_BUFLEN		8192

struct logfile {
	char *label;			/* user-defined label */
	pthread_mutex_t log_lock;	/* synchronising lock */
	struct {			/* private data, for abstraction */
		FILE *fp;		/* logfile */
		char *path;		/* logfile path */
		char *buf;		/* working buffer */
	} p;
};

extern	void logfile_init(struct logfile *lf);
extern	void logfile_destroy(struct logfile *lf);
extern	void logfile_open(struct logfile *lf, const char *path);
extern	void logfile_close(struct logfile *lf);
extern	void logfile_flush(struct logfile *lf);
extern	void logfile_printf(struct logfile *lf, const char *fmt, ...);

#endif	/* __LUSCA_LOGGING_H__ */
