#!/bin/bash

set -e -u -x -o pipefail

VERSION=${1:-stable}

rustup run ${VERSION} cargo test --verbose

./.github/workflows/cli_test.sh ${VERSION}
