#!/bin/sh
# Record `snpguest display report` for every report fixture, into
# snpguest-display/<report>.txt. The snp crate's differential test
# (attest/snp/tests/snpguest.rs) compares its own parse with these.
#
#   usage: sh snpguest-display.sh <path to snpguest 0.10.0>
#
# snpguest does not build on aarch64 (its rdrand dependency is x86-only), so
# run this on an x86_64 machine; Milan, for the recorded files.
set -eu
SNPGUEST=${1:?usage: snpguest-display.sh <snpguest>}
cd "$(dirname "$0")"
mkdir -p snpguest-display
"$SNPGUEST" --version > snpguest-display/VERSION
for r in report-*.bin; do
    "$SNPGUEST" display report "$r" > "snpguest-display/${r%.bin}.txt"
done
