AUTOMAKE_OPTIONS = foreign

EXTRA_DIST = $(man_MANS)
INCLUDES = -I../include -I../llcdb
CFLAGS = -Wall

lib_LTLIBRARIES = liblar.la
bin_PROGRAMS = llookup
sbin_PROGRAMS = lard

liblar_la_LDFLAGS = -Wc,-nostartfiles -release $(VERSION)
liblar_la_SOURCES = lar.c lar_unix.c lar_ebcdic.c

llookup_LDADD = -llar
llookup_SOURCES = llookup.c

lard_LDADD = -llar
lard_SOURCES = lard.c lard_load.c lar_list.c lar_timer.c \
	lar_vector.c lar_hosts.c

include_HEADERS = lar.h
noinst_HEADERS = lard.h lard_load.h llookup.h lar_unix.h lar_list.h \
	lar_timer.h lar_vector.h lar_ebcdic.h

man_MANS = lar.3 lard.8 llookup.8

$(OBJECTS): libtool
libtool: $(LIBTOOL_DEPS)
	$(SHELL) ./config.status --recheck
