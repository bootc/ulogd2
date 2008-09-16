
AM_CPPFLAGS = $(all_includes) -I$(top_srcdir)/include \
	      -DULOGD_CONFIGFILE="\"$(sysconfdir)/ulogd.conf\"" \
	      -DULOGD_LOGFILE_DEFAULT="\"$(localstatedir)/log/ulogd.log\""

sbin_PROGRAMS = ulogd

ulogd_SOURCES = ulogd.c ifi.c select.c timer.c signal.c conffile.c
ulogd_LDFLAGS = -export-dynamic -lpthread
