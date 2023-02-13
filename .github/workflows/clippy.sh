#!/bin/bash

set -e -u -o pipefail

VERSION=${1:-stable}

rustup run ${VERSION} cargo clippy -- -A clippy::new_without_default --deny warnings

# Suppress uninlined_format_args since assert! has a format! macro in it, which confuses clippy.
rustup run ${VERSION} cargo clippy --tests -- -A clippy::new_without_default -A clippy::expect_fun_call -A clippy::uninlined_format_args
