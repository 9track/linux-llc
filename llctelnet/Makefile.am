AUTOMAKE_OPTIONS = foreign

EXTRA_DIST = $(man_MANS)
INCLUDES   = -I../include
CFLAGS     = -Wall

bin_PROGRAMS  = llctelnet
sbin_PROGRAMS = llctelnetd

llctelnet_SOURCES = llctelnet.c
llctelnetd_SOURCES = llctelnetd.c

include_HEADERS =
noinst_HEADERS  = 

man_MANS = 

$(OBJECTS): libtool
libtool: $(LIBTOOL_DEPS)
	$(SHELL) ./config.status --recheck
