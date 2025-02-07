#!/bin/bash

set -e -u -x -o pipefail

VERSION=${1:-stable}

echo ${PATH}
ldd `which secilc`
ls /usr/local/bin

rustup run ${VERSION} cargo test --verbose

./.github/workflows/cli_test.sh ${VERSION}
