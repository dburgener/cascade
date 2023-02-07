#!/bin/bash

set -e -u -o pipefail

VERSION=${1:-stable}

rustup run ${VERSION} cargo test --verbose

./.github/workflows/cli_test.sh ${VERSION}
