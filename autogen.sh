#! /bin/sh

# helps bootstrapping libtool, when checked out from CVS
# requires GNU autoconf and GNU automake

file=Makefile.in

rm -f libtool

#libtoolize -c		# use when required (ie libtool upgrade)
aclocal
automake --gnu --add-missing --copy
autoconf

for sub in llcdb llcping llctftp llctelnet lar dlsw; do
  cd $sub
  aclocal
  automake --add-missing --include-deps
  autoconf
  cd ..
done

exit 0
