AUTOMAKE_OPTIONS = foreign

EXTRA_DIST = $(man_MANS)
AM_CPPFLAGS=-I$(srcdir)/../include

sbin_PROGRAMS = dlswd

dlswd_SOURCES = dlswd.c dlswd_load.c dlsw_list.c dlsw_vector.c dlsw_timer.c \
	dlsw_ssp.c

include_HEADERS = 
noinst_HEADERS = dlswd.h dlswd_load.h dlsw_list.h dlsw_vector.h dlsw_timer.h \
	dlsw_ssp.h

man_MANS = dlswd.8

$(OBJECTS): libtool
libtool: $(LIBTOOL_DEPS)
	$(SHELL) ./config.status --recheck
