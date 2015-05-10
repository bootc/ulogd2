
AM_CPPFLAGS = -I$(top_srcdir)/include ${LIBNETFILTER_LOG_CFLAGS}
AM_CFLAGS = ${regular_CFLAGS}

pkglib_LTLIBRARIES = ulogd_inppkt_UNIXSOCK.la

if BUILD_ULOG
pkglib_LTLIBRARIES += ulogd_inppkt_ULOG.la
endif

if BUILD_NFLOG
pkglib_LTLIBRARIES += ulogd_inppkt_NFLOG.la
endif

ulogd_inppkt_NFLOG_la_SOURCES = ulogd_inppkt_NFLOG.c
ulogd_inppkt_NFLOG_la_LDFLAGS = -avoid-version -module $(LIBNETFILTER_LOG_LIBS)

ulogd_inppkt_ULOG_la_SOURCES = ulogd_inppkt_ULOG.c
ulogd_inppkt_ULOG_la_LDFLAGS = -avoid-version -module
ulogd_inppkt_ULOG_la_LIBADD = ../../libipulog/libipulog.la

ulogd_inppkt_UNIXSOCK_la_SOURCES = ulogd_inppkt_UNIXSOCK.c
ulogd_inppkt_UNIXSOCK_la_LDFLAGS = -avoid-version -module
