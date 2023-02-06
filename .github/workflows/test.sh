#!/bin/bash

set -e -u -o pipefail

VERSION=${1:-stable}

rustup run ${VERSION} cargo test --verbose

# CLI tests
rustup run ${VERSION} cargo build --verbose

# TODO add additional targets to tests when ready
for d in debug
do
    ./target/$d/casc --help
    ./target/$d/casc -h

    ./target/$d/casc --version
    ./target/$d/casc -v

    ./target/$d/casc data/policies/simple.cas
    if [[ ! -f out.cil ]] ; then
        echo "Failed to create out.cil"
        exit 1
    fi

    ./target/$d/casc data/policies/simple.cas -o new.cil
    if [[ ! -f new.cil ]] ; then
        echo "Failed to create new.cil"
        exit 1
    fi

    ./target/$d/casc data/policies/simple.cas --color always
    ./target/$d/casc data/policies/simple.cas --color auto
    ./target/$d/casc data/policies/simple.cas --color never
done
