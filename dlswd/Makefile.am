AUTOMAKE_OPTIONS = foreign

EXTRA_DIST = $(man_MANS)
INCLUDES=-I../include -I../dlswmon

sbin_PROGRAMS = dlswd

dlswd_LDADD = -lproc
dlswd_SOURCES = dlswd.c dlsw_load.c dlsw_monitor.c

include_HEADERS = dlswd.h dlsw_load.h dlsw_monitor.h dlsw_proto.h

man_MANS = dlswd.8

$(OBJECTS): libtool
libtool: $(LIBTOOL_DEPS)
	$(SHELL) ./config.status --recheck
