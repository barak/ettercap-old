#!/bin/sh
mkdir -p libltdl/m4
autoreconf --install --force
# when not preparing a tarball, consider instead:
# autoreconf --symlink --install
