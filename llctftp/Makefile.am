AUTOMAKE_OPTIONS = foreign

EXTRA_DIST = $(man_MANS)
INCLUDES   = -I../include
CFLAGS     = -Wall

bin_PROGRAMS  = llctftp
sbin_PROGRAMS = llctftpd

llctftp_SOURCES  = llctftp.c
llctftpd_SOURCES = llctftpd.c

include_HEADERS =
noinst_HEADERS  =

man_MANS =

$(OBJECTS): libtool
libtool: $(LIBTOOL_DEPS)
	$(SHELL) ./config.status --recheck
