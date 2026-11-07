#!/bin/bash
# One-command rerun of the whole pack, from a clean checkout of this
# directory (plus the pinned reference tree under src/ref-mldsa and the
# FIPS 204 PDF). Run from the pack root directory.
#   bash run_all.sh
# Steps: rebuild the reference driver, run the context/prehash harness,
# run the ACVP KAT validation, regenerate SHA256SUMS over the outputs.
# Exit code is non-zero if any step fails or any case mismatches.
# The venv is NOT recreated here (offline-safe): create it once with
#   python3 -m venv venv && venv/bin/pip install \
#       "liboqs-python==0.16.0.2" "cryptography==50.0.2"
# and re-run this script. Expected end state: run_harness.py prints
# "RESULT: OK" (45/45 cases) and run_kat.py prints "RESULT: OK"
# (50/50 vectors).
set -e
set -o pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"
bash src/build_drivers.sh
./venv/bin/python run_harness.py 2>&1 | tee outputs/run_harness.log
./venv/bin/python run_kat.py 2>&1 | tee outputs/run_kat.log
./venv/bin/python src/render_index.py
./venv/bin/python src/check_index.py
(cd outputs && sha256sum results.json kat_results.json run_harness.log \
  run_kat.log artifacts/*.bin raw/FIPS-204.pdf raw/FIPS-204.txt \
  > SHA256SUMS)
(cd outputs && sha256sum -c SHA256SUMS)
echo "RUN_ALL: OK"
