#!/bin/sh

set -e

echo

if test ! -f ./configure; then
   echo "ERROR: configure not found..." >&2
   echo "Running autogen.sh to generate the autoscripts"
   if test ! -f ./autogen.sh; then
      echo "FATAL: autogen.sh not found." >&2
      exit
   fi
   ./autogen.sh
fi

if test "$1" = "--renew"; then
   shift
   ./autogen.sh
fi

echo "Configuring ettercap for maintainers mode..."
echo 
./configure --enable-debug --enable-maintainer-mode $*

echo
echo "Making ettercap to be tested in the current directory"
echo 
make test
