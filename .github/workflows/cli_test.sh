#!/bin/bash

set -e -u -o pipefail

VERSION=${1:-stable}

check_file () {
    if [[ ! -f "$1" ]] ; then
        echo "Failed to create $1"
        exit 1
    fi
    rm -f "$1"
}

# CLI tests
rustup run ${VERSION} cargo build --verbose

# TODO add additional targets to tests when ready
for d in debug
do
    ./target/$d/casc --help
    ./target/$d/casc -h

    ./target/$d/casc --version
    ./target/$d/casc -V

    ./target/$d/casc data/policies/simple.cas
    check_file out.cil

    ./target/$d/casc data/policies/simple.cas -o new.cil
    check_file new.cil

    ./target/$d/casc data/policies/simple.cas --color always
    check_file out.cil
    ./target/$d/casc data/policies/simple.cas --color auto
    check_file out.cil
    ./target/$d/casc data/policies/simple.cas --color never
    check_file out.cil
done
