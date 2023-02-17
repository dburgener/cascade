#!/bin/bash

set -e -u -o pipefail

rustup run stable cargo build --release --verbose
