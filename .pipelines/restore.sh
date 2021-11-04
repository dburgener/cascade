#!/bin/bash

set -e -u -o pipefail

# https://nickb.dev/blog/azure-pipelines-for-rust-projects
curl --proto '=https' -sSf https://sh.rustup.rs | sh -s -- -y
export PATH="${PATH}:${HOME}/.cargo/bin"
echo "##vso[task.setvariable variable=PATH;]${PATH}"

rustup toolchain install nightly

# secilc is in EPEL
yum -y install epel-release

# gcc needed for rust linking
yum -y install gcc secilc