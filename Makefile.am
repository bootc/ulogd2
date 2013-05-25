
ACLOCAL_AMFLAGS  = -I m4

man_MANS = ulogd.8 ulogd.conf.5

EXTRA_DIST = $(man_MANS) ulogd.logrotate ulogd.spec ulogd.conf.in doc

AM_CPPFLAGS = -I$(top_srcdir)/include
SUBDIRS = include libipulog src input filter output

noinst_DATA = ulogd.conf

edit = sed \
	-e 's,@pkglibdir\@,${pkglibdir},g'

ulogd.conf: Makefile $(srcdir)/ulogd.conf.in
	$(edit) $(srcdir)/ulogd.conf.in >ulogd.conf

dist-hook:
	rm -f ulogd.conf

