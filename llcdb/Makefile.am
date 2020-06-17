AUTOMAKE_OPTIONS = foreign

EXTRA_DIST = $(man_MANS)
AM_CPPFLAGS = -I$(srcdir)/../include -fPIC
AM_CFLAGS = -Wall

lib_LTLIBRARIES = libllcdb.la

libllcdb_la_LDFLAGS = -Wc,-nostartfiles -release $(VERSION)
libllcdb_la_SOURCES = llcdb.c

include_HEADERS = llcdb.h
noinst_HEADERS =

man_MANS =

$(OBJECTS): libtool
libtool: $(LIBTOOL_DEPS)
	$(SHELL) ./config.status --recheck
