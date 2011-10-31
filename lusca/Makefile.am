AUTOMAKE_OPTIONS = foreign no-dependencies

LDADD = $(LIBEVENT_GC_SECTIONS) ../libevent.la
AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/compat -I$(top_srcdir)/include -I../include

noinst_PROGRAMS = lusca

lusca_SOURCES = access_log.c log.c logging.c dns.c main.c lusca.c utils.c

verify:

DISTCLEANFILES = *~
