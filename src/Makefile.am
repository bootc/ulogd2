
AM_CPPFLAGS = -I$(top_srcdir)/include \
	      -DULOGD_CONFIGFILE="\"$(sysconfdir)/ulogd.conf\"" \
	      -DULOGD_LOGFILE_DEFAULT="\"$(localstatedir)/log/ulogd.log\""
AM_CFLAGS = ${regular_CFLAGS}

sbin_PROGRAMS = ulogd

ulogd_SOURCES = ulogd.c select.c timer.c rbtree.c conffile.c hash.c addr.c
ulogd_LDADD   = ${libdl_LIBS} ${libpthread_LIBS}
ulogd_LDFLAGS = -export-dynamic
