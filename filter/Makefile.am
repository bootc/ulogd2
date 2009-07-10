SUBDIRS = raw2packet packet2flow

INCLUDES = $(all_includes) -I$(top_srcdir)/include

pkglib_LTLIBRARIES = ulogd_filter_PWSNIFF.la ulogd_filter_PRINTPKT.la \
			ulogd_filter_PRINTFLOW.la ulogd_filter_STATIC.la

ulogd_filter_PWSNIFF_la_SOURCES = ulogd_filter_PWSNIFF.c
ulogd_filter_PWSNIFF_la_LDFLAGS = -module -avoid-version

ulogd_filter_PRINTPKT_la_SOURCES = ulogd_filter_PRINTPKT.c ../util/printpkt.c
ulogd_filter_PRINTPKT_la_LDFLAGS = -module -avoid-version

ulogd_filter_PRINTFLOW_la_SOURCES = ulogd_filter_PRINTFLOW.c ../util/printflow.c
ulogd_filter_PRINTFLOW_la_LDFLAGS = -module -avoid-version

ulogd_filter_STATIC_la_SOURCES = ulogd_filter_STATIC.c
ulogd_filter_STATIC_la_LDFLAGS = -module -avoid-version
