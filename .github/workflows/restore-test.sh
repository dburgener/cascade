#!/bin/bash

set -e -u -o pipefail

# Manually build secilc, rather than take the packaged version, so we can have control over version
# Github actions will have already checked out the repo to the correct tag for this run
sudo apt install -y --no-install-recommends flex bison pkg-config libaudit-dev libbz2-dev libustr-dev libpcre3-dev xmlto

pushd selinux

sudo make -j16 -C libsepol install
sudo make -j16 -C secilc install
