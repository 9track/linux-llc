## Process this file with automake to produce Makefile.in

AUTOMAKE_OPTIONS = 1.3e foreign

BUILD_SUBDIRS = . include docs llcdb llcping llctftp llctelnet lar dlsw
SUBDIRS = $(BUILD_SUBDIRS)
DIST_SUBDIRS = $(BUILD_SUBDIRS) $(CONF_SUBDIRS)

# We need to export these variables
CFLAGS = @CFLAGS@
CPPLAGS = @CPPFLAGS@
LDFLAGS = @LDFLAGS@
LIBS= @LIBS@

EXTRA_DIST = mkstamp BUGS isapplied patch-o-matic autogen.sh chgver.sh
CLEANFILES = libtool

# Patch-o-matic happenings
KERNEL_DIR='\/usr\/src\/linux'
PENDING_PATCHES:=netbeui+8022.patch llc_sock.patch
export KERNEL_DIR

# CVS happenings
#ifndef CVS
CVS="cvs"
#endif

# RPM happenings
#ifndef RPM_BUILD_DIR
RPM_BUILD_DIR="/usr/src/rpm"
#endif
#ifndef RPM_BUILD_TARGET
RPM_BUILD_TARGET=`uname -m`
#endif

################################################################
##
## Everything past here is useful to the maintainer, but probably not
## to anybody else (snarfed from automake/Makefile.am).
##

new-version:
	find . \( -name configure.in \) -type f -exec ./chgver.sh {} $(RELEASE) \;


# Tag before making distribution.  Also, don't make a distribution if
# checks fail.  Also, make sure the NEWS file is up-to-date.

cvs-dist:
	@if sed '1,2d;3q' $(srcdir)/NEWS | grep -e "$(VERSION)" > /dev/null; then :; else \
	  echo "NEWS not updated; not releasing" 1>&2; \
	  exit 1;				\
	fi
	cd $(srcdir) && \
	 $(CVS) tag `echo "RELEASE-$(VERSION)" | sed 's/\./-/g'`
	$(MAKE) dist

cvs-diff:
	thisver=`echo "release-$(VERSION)" | sed 's/\./-/g'`; \
	if test -z "$$OLDVERSION"; then \
	  prevno=`echo "$(VERSION)" - 0.01 | bc | sed 's/^\./0./'`; \
	else prevno="$$OLDVERSION"; fi; \
	prevver=release-`echo $$prevno | sed 's/\./-/g'`; \
	$(CVS) -f rdiff -c -r $$prevver -r $$thisver $(PACKAGE) \
	    > $(PACKAGE)-$$prevno-$(VERSION).diff

pending-patches:
	@cd patch-o-matic && KERNEL_DIR=$(KERNEL_DIR) ./runme $(PENDING_PATCHES)

rpm-dist:
	if ! test -f $(srcdir)/docs/$(PACKAGE).spec; then \
		echo "RPM spec file '$(PACKAGE).spec' missing from '$(srcdir)/docs' directory; aborting rpm build" 1>&2; \
		exit 1; \
	fi; \
	cat $(srcdir)/docs/$(PACKAGE).spec | sed s/VERSION/$(VERSION)/g > $(RPM_BUILD_DIR)/SPECS/$(PACKAGE).spec; \
	$(MAKE) dist; \
	cp -f $(srcdir)/$(PACKAGE)-$(VERSION).tar.gz $(RPM_BUILD_DIR)/SOURCES/$(PACKAGE)-$(VERSION).tar.gz; \
	rpm -ba -v $(RPM_BUILD_DIR)/SPECS/$(PACKAGE).spec; \
	rm -f $(RPM_BUILD_DIR)/SPECS/$(PACKAGE).spec; \
	rm -f $(RPM_BUILD_DIR)/SOURCES/$(PACKAGE)-$(VERSION).tar.gz; \
	rm -rf $(RPM_BUILD_DIR)/BUILD/$(PACKAGE)-$(VERSION); \
	mkdir $(srcdir)/build.tmp
	mkdir $(srcdir)/build.tmp/source
	mkdir $(srcdir)/build.tmp/binaries
	mkdir $(srcdir)/build.tmp/binaries/RPMS
	mkdir $(srcdir)/build.tmp/binaries/SRPMS
	mv -f $(PACKAGE)-$(VERSION).tar.gz $(srcdir)/build.tmp/source
	mv -f `find $(RPM_BUILD_DIR)/SRPMS -name "$(PACKAGE)-*.src.rpm" -print` $(srcdir)/build.tmp/binaries/SRPMS/; \
	mv -f `find $(RPM_BUILD_DIR)/RPMS -name "$(PACKAGE)-*.rpm" -print` $(srcdir)/build.tmp/binaries/RPMS/

ftp-dist:
	if ! test -d $(srcdir)/build.tmp; then \
		echo "Build directory '$(srcdir)/build.tmp' missing, run 'make rpm-dist' first" 1>&2; \
		exit 1; \
	fi; \
	ncftpput -R -u jschlst ftp.linux-sna.org /home/ftp/pub/$(PACKAGE)/v0.1/ $(srcdir)/build.tmp/*

clean-dist:
	rm -rf $(srcdir)/build.tmp
