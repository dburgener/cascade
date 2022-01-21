#!/bin/bash

set -e -u -o pipefail

rustup run stable cargo clippy -- -A clippy::new_without_default
