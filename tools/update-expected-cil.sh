#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# SPDX-License-Identifier: MIT

set -u -e -o pipefail

cd "$(dirname -- "$0")/.."

cargo build --bin casc

for f in data/policies/*.cas; do
	printf '[ ] %s' "$f"
	if ./target/debug/casc "$f" 2>/dev/null; then
		mv out.cil "data/expected_cil/$(basename -- "${f%%.cas}").cil"
		printf '\r[+]\n'
	else
		rm out.cil
		printf '\r[-]\n'
	fi
done
