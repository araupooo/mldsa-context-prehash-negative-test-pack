#!/bin/bash
# Build the dilithium reference driver from the pinned commit.
# Run from the pack root directory.
# Requires: git, gcc.
# The reference tree is cloned at the pinned commit if absent;
# if present, it is checked out at the pinned commit (no network
# needed for a rebuild).
set -e
HERE="$(cd "$(dirname "$0")/.." && pwd)"
REF="$HERE/src/ref-mldsa"
PIN="d35ba3fe5449bee3e6d43e1f296c3ca818bd36be"
if [ ! -d "$REF" ]; then
  git clone https://github.com/pq-crystals/dilithium.git "$REF"
fi
if [ -d "$REF/.git" ]; then
  git -C "$REF" checkout -q "$PIN"
else
  # Bundled tree (pack/repo copies ship without .git): the pinned
  # commit is recorded in src/ref-mldsa/COMMIT; build as-is.
  echo "bundled ref tree, no .git; pinned commit per src/ref-mldsa/COMMIT: $(cat "$REF/COMMIT" 2>/dev/null || echo unknown)"
fi
gcc -O2 -std=c99 -Wall -I"$REF/ref" -o "$HERE/ref_mldsa_driver" \
  "$HERE/src/ref_mldsa_driver.c" \
  "$REF/ref/randombytes.c" "$REF/ref/sign.c" \
  "$REF/ref/packing.c" "$REF/ref/polyvec.c" \
  "$REF/ref/poly.c" "$REF/ref/ntt.c" \
  "$REF/ref/reduce.c" "$REF/ref/rounding.c" \
  "$REF/ref/fips202.c" "$REF/ref/symmetric-shake.c"
echo "built: ref_mldsa_driver (dilithium $PIN, DILITHIUM_MODE 2, ML-DSA-44)"
"$HERE/ref_mldsa_driver" 2>&1 | head -2 || true
