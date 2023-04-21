#!/bin/bash

set -e -u -o pipefail

VERSION=${1:-stable}

# https://nickb.dev/blog/azure-pipelines-for-rust-projects
curl --proto '=https' -sSf https://sh.rustup.rs | sh -s -- -y
export PATH="${PATH}:${HOME}/.cargo/bin"
echo "##vso[task.setvariable variable=PATH;]${PATH}"

rustup toolchain install ${VERSION}
rustup component add rustfmt --toolchain ${VERSION}

