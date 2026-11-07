#!/usr/bin/env python3
"""Verify index.html against outputs/results.json + kat_results.json.

Checks that every case row in results.json appears in index.html with
the same expected/observed values, that the headline counts match,
and that the KAT table matches kat_results.json. Exit 0 when
everything matches; prints each mismatch otherwise.
Usage: ./venv/bin/python src/check_index.py
"""
import html as _html
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RES = json.load(open(os.path.join(HERE, "outputs", "results.json")))
KAT = json.load(open(os.path.join(HERE, "outputs", "kat_results.json")))
HTML = open(os.path.join(HERE, "index.html")).read()

fails = []


def check(cond, msg):
    print(("OK   " if cond else "FAIL ") + msg)
    if not cond:
        fails.append(msg)


# headline counts
check("Harness cases: %d, matched expected outcome: %d, mismatches: %d."
      % (RES["counts"]["total"], RES["counts"]["matched"],
         len(RES["counts"]["mismatches"])) in HTML,
      "headline harness counts")
check("Valid-agreement cases: %d VALID as expected; negative/error "
      "cases: %d rejected or failed as expected; N/A probes: %d."
      % (sum(1 for c in RES["cases"] if c["expected"] == "VALID"),
         sum(1 for c in RES["cases"]
             if c["expected"] in ("INVALID", "ERROR")),
         sum(1 for c in RES["cases"] if c["expected"] == "N/A")) in HTML,
      "headline case breakdown")

# every case row: id, title, implementation, expected, observed
cells = [_html.unescape(x) for x in
         re.findall(r"<td>(.*?)</td>", HTML, re.S)]
for c in RES["cases"]:
    want = [c["id"], c["title"], c["implementation"],
            c["expected"], c["observed"]]
    # rows are consecutive 6-cell groups; check the 5 values appear
    # consecutively in the flattened cell list
    found = any(cells[i:i + 5] == want for i in range(len(cells) - 4))
    check(found, "case row %s (%s / %s)" % (c["id"], c["expected"],
                                            c["observed"]))

# KAT table
for kind in ("sigGen", "sigVer", "keyGen"):
    v = KAT[kind]
    want = "<td>%s</td><td>%d</td><td>%d</td><td>%d</td>" % (
        kind, len(v), sum(1 for t in v if t["match"]),
        sum(1 for t in v if not t["match"]))
    check(want in HTML, "KAT row %s" % kind)

# implementation table values
check(RES["implementations"]["dilithium_ref"]["commit"] in HTML,
      "ref commit in page")
check(RES["fips204"]["sha256"] in HTML, "FIPS 204 sha256 in page")

print("checked %d cases + KAT + headers; failures: %d"
      % (len(RES["cases"]), len(fails)))
sys.exit(1 if fails else 0)
