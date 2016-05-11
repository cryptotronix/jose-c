#!/bin/bash

if [ $# -eq 0 ]; then
    echo "Usage: $0 package version destdir specfile"
    exit 1
fi

PACKAGE=$1
VERSION=$2
DESTDIR=$3
SPECFILE=$4

is_ok() {
    if [ $? -ne 0 ]; then
        echo "Died at $1"
        exit 1
    fi
    echo "$1 OK"
}

echo "Upstream $PACKAGE-$VERSION"

RELEASE=$(grep Release $SPECFILE | awk '{ print $2 }')
RPMDIR=$(rpm --eval %_rpmdir)
SRCRPMDIR=$(rpm --eval %_srcrpmdir)
RPMARCH=$(rpm --eval %_target_cpu)
BINRPM=$PACKAGE-$VERSION-$RELEASE.$RPMARCH.rpm

echo "$RPMDIR"
echo "$SRCRPMDIR"
echo "$RPMARCH"
echo "$RELEASE"
echo "$BINRPM"
echo "$DESTDIR"

rpmbuild -ta --define '_sbindir /usr/sbin' \
         --define '_bindir /usr/bin' \
         --clean $PACKAGE-$VERSION.tar.gz

is_ok "RPM Build"

if [ -e $RPMDIR/$BINRPM ]; then
    echo "Copying binrpm"
    cp $RPMDIR/$BINRPM $DESTDIR
    is_ok "copy rpm"
fi

if [ -e $RPMDIR/$RPMARCH/$BINRPM ]; then
    echo "Copying march binrpm"
    cp $RPMDIR/$RPMARCH/$BINRPM $DESTDIR
    is_ok "copy rpm"
fi
