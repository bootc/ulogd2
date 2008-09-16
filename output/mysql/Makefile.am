INCLUDES = $(all_includes) -I$(top_srcdir)/include $(MYSQL_INC)
LIBS=$(MYSQL_LIB)

if HAVE_MYSQL

pkglib_LTLIBRARIES = ulogd_output_MYSQL.la

ulogd_output_MYSQL_la_SOURCES = ulogd_output_MYSQL.c
ulogd_output_MYSQL_la_LDFLAGS = -module

endif
