AUTOMAKE_OPTIONS = foreign

EXTRA_DIST = $(man_MANS)
AM_CPPFLAGS = -I$(srcdir)/../include -I$(srcdir)/../llcdb
AM_CFLAGS = -Wall

bin_PROGRAMS = llcping
sbin_PROGRAMS = llcpingd

llcping_LDADD = -L../llcdb -lllcdb
llcping_SOURCES = llcping.c
llcpingd_SOURCES = llcpingd.c llcpingd_load.c

include_HEADERS =
noinst_HEADERS = llcping.h llcpingd.h llcpingd_load.h

man_MANS = llcping.8 llcpingd.8

$(OBJECTS): libtool
libtool: $(LIBTOOL_DEPS)
	$(SHELL) ./config.status --recheck
