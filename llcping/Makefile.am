AUTOMAKE_OPTIONS = foreign

EXTRA_DIST = $(man_MANS) start.sh
INCLUDES=-I../include

bin_PROGRAMS = llcping llcpingd llcpingd2

llcping_SOURCES = llcping.c

llcpingd_SOURCES = llcpingd.c

llcpingd2_SOURCES = llcpingd2.c

include_HEADERS =

man_MANS = llcping.8

$(OBJECTS): libtool
libtool: $(LIBTOOL_DEPS)
	$(SHELL) ./config.status --recheck
