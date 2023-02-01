#!/bin/bash

set -e -u -o pipefail

VERSION=${1:-stable}

# Manually build secilc, rather than take the packaged version, so we can have control over version
# Github actions will have already checked out the repo to the correct tag for this run
sudo apt update
sudo apt install -y --no-install-recommends flex bison pkg-config libaudit-dev libbz2-dev libustr-dev libpcre3-dev xmlto

pushd selinux

# 3.2 and earlier have a warning fro stringop-truncation
# 3.0 and earlier have multiple definitions of global variables, which fails to
# compile with -fno-common, which is the default behavior in modern GCC.  This
# was fixed upstream in commit a96e8c59ecac84096d870b42701a504791a8cc8c, but
# for our purposes compiling the older versions, we can just allow the behavior
# with -fcommon
sudo make -j16 CFLAGS="-Wno-error=stringop-truncation -fcommon -pipe -fPIC" -C libsepol install
sudo make -j16 -C secilc install

# https://nickb.dev/blog/azure-pipelines-for-rust-projects
curl --proto '=https' -sSf https://sh.rustup.rs | sh -s -- -y
export PATH="${PATH}:${HOME}/.cargo/bin"
echo "##vso[task.setvariable variable=PATH;]${PATH}"

rustup toolchain install ${VERSION}
