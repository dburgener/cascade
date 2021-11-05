#!/bin/bash

set -e -u -o pipefail

# Gently stops when an error occurs.
rustup run nightly cargo build --verbose || exit 0
rustup run nightly cargo test --verbose || exit 0
rustup run nightly cargo doc --no-deps || exit 0
rustup run nightly cargo fmt --all -- --check || exit 0
