#!/bin/bash

set -e -u -o pipefail

VERSION=${1:-stable}

rustup run ${VERSION} cargo clippy -- -A clippy::new_without_default --deny warnings

rustup run ${VERSION} cargo clippy --tests -- -A clippy::new_without_default -A clippy::expect_fun_call
