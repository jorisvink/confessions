#!/bin/sh
#
# Builds confessions using a mingw based toolchain for Windows.
#
# Note that it requires the compiler to be in PATH and that
# there exists a ~/src/mxe directory with the right packages
# compiled for pkg-config.
#

PKG_CONFIG_PATH=~/src/mxe/usr/x86_64-w64-mingw32.static/lib/pkgconfig \
    CC=x86_64-w64-mingw32.static-gcc OSNAME=windows \
    LIBKYRKA_PATH=~/src/libkyrka-windows make
