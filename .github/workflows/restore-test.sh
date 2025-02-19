#!/bin/bash

set -e -u -x -o pipefail

VERSION=${1:-stable}

# Manually build secilc, rather than take the packaged version, so we can have control over version
# Github actions will have already checked out the repo to the correct tag for this run
sudo apt update
apt-get install --no-install-recommends --no-install-suggests \
    bison \
    flex \
    gawk \
    gcc \
    gettext \
    make \
    libaudit-dev \
    libbz2-dev \
    libcap-dev \
    libcap-ng-dev \
    libcunit1-dev \
    libglib2.0-dev \
    libpcre2-dev \
    pkgconf \
    python3 \
    systemd \
    xmlto

pushd selinux

# 3.2 and earlier have a warning for stringop-truncation
# 3.0 and earlier have multiple definitions of global variables, which fails to
# compile with -fno-common, which is the default behavior in modern GCC.  This
# was fixed upstream in commit a96e8c59ecac84096d870b42701a504791a8cc8c, but
# for our purposes compiling the older versions, we can just allow the behavior
# with -fcommon
#sudo make DESTDIR=~/selinux_out LIBDIR=~/selinux_out/usr/lib LIBSEPOLA=~/selinux_out/usr/lib/libsepol.a LDFLAGS="-L~/selinux_out/usr/lib -L~/selinux_out/usr/lib" -j16 CFLAGS="-Wno-error=stringop-truncation -fcommon -pipe -fPIC -I~/selinux_out/usr/include" -C libsepol install
#sudo ls ~/selinux_out
#sudo ls ~/selinux_out/usr/include
#sudo ls ~/selinux_out/usr/include/sepol
#sudo ls ~/selinux_out/usr/include/sepol/cil
#sudo make DESTDIR=~/selinux_out LIBDIR=~/selinux_out/usr/lib LIBSEPOLA=~/selinux_out/usr/lib/libsepol.a CFLAGS="-I~/selinux_out/usr/include" LDFLAGS="-L~/selinux_out/usr/lib -L~/selinux_out/usr/lib" -j16 -C secilc install
sudo make CFLAGS="-Wno-error=stringop-truncation -fcommon -pipe -fPIC" OPT_SUBDIRS="" install

# https://nickb.dev/blog/azure-pipelines-for-rust-projects
curl --proto '=https' -sSf https://sh.rustup.rs | sh -s -- -y
export PATH="${PATH}:${HOME}/.cargo/bin"
echo "##vso[task.setvariable variable=PATH;]${PATH}"

rustup toolchain install ${VERSION}
