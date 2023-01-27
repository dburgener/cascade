#!/bin/bash

set -e -u -o pipefail

VERSION=${1:-stable}

rustup run ${VERSION} cargo fmt --all -- --check
