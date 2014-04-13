AM_CPPFLAGS = -I$(top_srcdir)/include ${LIBNETFILTER_ACCT_CFLAGS} \
              ${LIBNETFILTER_CONNTRACK_CFLAGS} ${LIBNETFILTER_LOG_CFLAGS}
AM_CFLAGS = ${regular_CFLAGS}

SUBDIRS= pcap mysql pgsql sqlite3 dbi

pkglib_LTLIBRARIES = ulogd_output_LOGEMU.la ulogd_output_SYSLOG.la \
			 ulogd_output_OPRINT.la ulogd_output_GPRINT.la \
			 ulogd_output_NACCT.la ulogd_output_XML.la \
			 ulogd_output_GRAPHITE.la

if HAVE_JANSSON
pkglib_LTLIBRARIES += ulogd_output_JSON.la
endif

ulogd_output_GPRINT_la_SOURCES = ulogd_output_GPRINT.c
ulogd_output_GPRINT_la_LDFLAGS = -avoid-version -module

ulogd_output_LOGEMU_la_SOURCES = ulogd_output_LOGEMU.c
ulogd_output_LOGEMU_la_LDFLAGS = -avoid-version -module

ulogd_output_SYSLOG_la_SOURCES = ulogd_output_SYSLOG.c
ulogd_output_SYSLOG_la_LDFLAGS = -avoid-version -module

ulogd_output_OPRINT_la_SOURCES = ulogd_output_OPRINT.c
ulogd_output_OPRINT_la_LDFLAGS = -avoid-version -module

ulogd_output_NACCT_la_SOURCES = ulogd_output_NACCT.c
ulogd_output_NACCT_la_LDFLAGS = -avoid-version -module

ulogd_output_XML_la_SOURCES = ulogd_output_XML.c
ulogd_output_XML_la_LIBADD  = ${LIBNETFILTER_LOG_LIBS} \
			      ${LIBNETFILTER_CONNTRACK_LIBS} \
			      ${LIBNETFILTER_ACCT_LIBS}
ulogd_output_XML_la_LDFLAGS = -avoid-version -module

ulogd_output_GRAPHITE_la_SOURCES = ulogd_output_GRAPHITE.c
ulogd_output_GRAPHITE_la_LDFLAGS = -avoid-version -module

if HAVE_JANSSON
ulogd_output_JSON_la_SOURCES = ulogd_output_JSON.c
ulogd_output_JSON_la_LIBADD  = ${libjansson_LIBS}
ulogd_output_JSON_la_LDFLAGS = -avoid-version -module
endif
