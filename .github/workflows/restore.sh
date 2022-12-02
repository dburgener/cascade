#!/bin/bash

set -e -u -o pipefail

# https://nickb.dev/blog/azure-pipelines-for-rust-projects
curl --proto '=https' -sSf https://sh.rustup.rs | sh -s -- -y
export PATH="${PATH}:${HOME}/.cargo/bin"
echo "##vso[task.setvariable variable=PATH;]${PATH}"

rustup toolchain install nightly

# Manually build secilc, rather than take the packaged version, so we can have control over version
# Github actions will have already checked out the repo to the correct tag for this run
sudo apt install -y --no-install-recommends flex bison pkg-config libaudit-dev libbz2-dev libustr-dev libpcre3-dev xmlto

pushd selinux

sudo make -j16 -C libsepol install
sudo make -j16 -C secilc install
