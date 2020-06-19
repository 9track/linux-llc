#! /bin/sh

# helps bootstrapping libtool, when checked out from CVS
# requires GNU autoconf and GNU automake

#libtoolize -c		# use when required (ie libtool upgrade)
aclocal
automake --gnu --add-missing --copy
autoconf

exit 0
