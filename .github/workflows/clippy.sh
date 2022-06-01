#!/bin/bash

set -e -u -o pipefail

rustup run stable cargo clippy -- -A clippy::new_without_default --deny warnings

rustup run stable cargo clippy --tests -- -A clippy::new_without_default -A clippy::expect_fun_call
