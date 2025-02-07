#!/bin/bash

set -e -u -x -o pipefail

VERSION=${1:-stable}

ldd `which secilc`

rustup run ${VERSION} cargo test --verbose

./.github/workflows/cli_test.sh ${VERSION}
