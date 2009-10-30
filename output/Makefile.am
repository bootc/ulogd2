INCLUDES = $(all_includes) -I$(top_srcdir)/include
LIBS=""

SUBDIRS= pcap mysql pgsql sqlite3 ipfix

pkglib_LTLIBRARIES = ulogd_output_LOGEMU.la ulogd_output_SYSLOG.la \
			ulogd_output_OPRINT.la ulogd_output_NACCT.la \
			ulogd_output_ASTARO.la

ulogd_output_LOGEMU_la_SOURCES = ulogd_output_LOGEMU.c
ulogd_output_LOGEMU_la_LDFLAGS = -module -avoid-version

ulogd_output_SYSLOG_la_SOURCES = ulogd_output_SYSLOG.c
ulogd_output_SYSLOG_la_LDFLAGS = -module -avoid-version

ulogd_output_OPRINT_la_SOURCES = ulogd_output_OPRINT.c
ulogd_output_OPRINT_la_LDFLAGS = -module -avoid-version

ulogd_output_NACCT_la_SOURCES = ulogd_output_NACCT.c
ulogd_output_NACCT_la_LDFLAGS = -module -avoid-version

ulogd_output_ASTARO_la_SOURCES = ulogd_output_ASTARO.c
ulogd_output_ASTARO_la_LDFLAGS = -module -avoid-version

