#!/bin/sh
#
# Script to take an change the version numbers in a configure.in script.
#
# make new-version RELEASE=1.00pre10
# find . \( -name configure.in \) -type f -exec ./chgver.sh {} $RELEASE \;

OLD_VER=`cat $1 | grep AM_INIT_AUTOMAKE | cut -d',' -f 2 | sed s/'^ '//g | sed s/\)//g`
sed s/${OLD_VER}/$2/g $1 > $1.tmp
mv $1.tmp $1
