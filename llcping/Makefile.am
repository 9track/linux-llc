AUTOMAKE_OPTIONS = foreign

EXTRA_DIST = $(man_MANS)
INCLUDES = -I../include
CFLAGS = -Wall

sbin_PROGRAMS = llcping llcpingd

llcping_SOURCES = llcping.c

llcpingd_LDADD = -lxml
llcpingd_SOURCES = llcpingd.c llcpingd_load.c

include_HEADERS = llcpingd.h llcpingd_load.h

man_MANS = llcping.8 llcpingd.8

$(OBJECTS): libtool
libtool: $(LIBTOOL_DEPS)
	$(SHELL) ./config.status --recheck
