AUTOMAKE_OPTIONS = foreign

EXTRA_DIST = $(man_MANS)
INCLUDES = -I../include -I../llcdb
CFLAGS = -Wall

lib_LTLIBRARIES = liblar.la
sbin_PROGRAMS = lard llookup

liblar_la_LDFLAGS = -Wc,-nostartfiles -release $(VERSION)
liblar_la_SOURCES = lar.c lar_unix.c

lard_LDADD = -llar
lard_SOURCES = lard.c lard_load.c lar_list.c

llookup_LDADD = -llar
llookup_SOURCES = llookup.c

include_HEADERS = lar.h
noinst_HEADERS = lard.h lard_load.h llookup.h lar_unix.h lar_list.h

man_MANS =

$(OBJECTS): libtool
libtool: $(LIBTOOL_DEPS)
	$(SHELL) ./config.status --recheck
