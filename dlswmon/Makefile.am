AUTOMAKE_OPTIONS = foreign

EXTRA_DIST = $(man_MANS)
INCLUDES=-I../include -I../dlswd

bin_PROGRAMS = dlswmon

dlswmon_LDADD = -lproc
dlswmon_SOURCES = dlswmon.c cmdtab.c parse.c

include_HEADERS = dlswmonitor.h commands.h parse.h

man_MANS = dlswmon.8

$(OBJECTS): libtool
libtool: $(LIBTOOL_DEPS)
	$(SHELL) ./config.status --recheck
