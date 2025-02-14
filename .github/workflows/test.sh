#!/bin/bash

set -e -u -x -o pipefail

VERSION=${1:-stable}

echo ${PATH}
LD_LIBRARY_PATH=~/selinux:$LD_LIBRARY_PATH ldd `which secilc`
ls /usr/local/bin

LD_LIBRARY_PATH=~/selinux:$LD_LIBRARY_PATH rustup run ${VERSION} cargo test --verbose

./.github/workflows/cli_test.sh ${VERSION}
