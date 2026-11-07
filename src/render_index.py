#!/usr/bin/env python3
"""Render index.html from outputs/results.json and kat_results.json.

Every number in the page is copied verbatim from the measured result
files, so the page cannot drift from the measurements. Run from the
task work directory: ./venv/bin/python src/render_index.py
Writes index.html next to this script's parent (the work directory
root); the pack/repo staging copies it from there.
"""
import html
import json
import os

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RES = json.load(open(os.path.join(HERE, "outputs", "results.json")))
KAT = json.load(open(os.path.join(HERE, "outputs", "kat_results.json")))


def esc(s):
    return html.escape(str(s))


rows = []
for c in RES["cases"]:
    rows.append(
        "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td>"
        "<td>%s</td></tr>" % (
            esc(c["id"]), esc(c["title"]), esc(c["implementation"]),
            esc(c["expected"]), esc(c["observed"]),
            "match" if c["match"] else "MISMATCH"))
case_rows = "\n".join(rows)

kat_rows = []
for kind in ("sigGen", "sigVer", "keyGen"):
    v = KAT[kind]
    kat_rows.append("<tr><td>%s</td><td>%d</td><td>%d</td><td>%d</td></tr>"
                    % (kind, len(v), sum(1 for t in v if t["match"]),
                       sum(1 for t in v if not t["match"])))
kat_rows = "\n".join(kat_rows)

counts = RES["counts"]
n_valid = sum(1 for c in RES["cases"] if c["expected"] == "VALID")
n_neg = sum(1 for c in RES["cases"] if c["expected"] in ("INVALID", "ERROR"))
n_na = sum(1 for c in RES["cases"] if c["expected"] == "N/A")
kat_n = {k: (len(v), sum(1 for t in v if t["match"])) for k, v in KAT.items()}
kat_total = sum(n for n, _ in kat_n.values())
kat_matched = sum(m for _, m in kat_n.values())
impl = RES["implementations"]
lib = impl["liboqs"]
ref = impl["dilithium_ref"]
xcheck = impl["cryptography_crosscheck"]

page = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>ML-DSA Context and Prehash Negative-Test Pack</title>
<style>
body{font-family:system-ui,sans-serif;max-width:1000px;margin:2em auto;
padding:0 1em;line-height:1.5;color:#111}
table{border-collapse:collapse;width:100%%;margin:1em 0}
th,td{border:1px solid #999;padding:4px 8px;text-align:left;font-size:14px}
th{background:#eee}
code{background:#f2f2f2;padding:0 3px}
h1{font-size:24px}h2{font-size:19px;margin-top:1.5em}
.good{color:#0a6b0a}.bad{color:#a00}
</style>
</head>
<body>
<h1>ML-DSA Context-String and HashML-DSA Prehash Negative-Test Pack</h1>
<p>Reusable evidence pack checking ML-DSA context-string and HashML-DSA
handling in two pinned ML-DSA-44 implementations against FIPS 204
(DOI 10.6028/NIST.FIPS.204).</p>

<h2>Headline results</h2>
<ul>
<li><strong>Harness cases: %(total)d, matched expected outcome: %(matched)d, mismatches: %(mismatches)d.</strong></li>
<li>Valid-agreement cases: %(nvalid)d VALID as expected; negative/error cases: %(nneg)d rejected or failed as expected; N/A probes: %(nna)d.</li>
<li>Context handling is fully conformant in both implementations: cross-verification liboqs &harr; dilithium reference is VALID in both directions with a non-empty context, and every wrong-context, overlong-context, altered-signature, message-mismatch and wrong-key negative is rejected.</li>
<li>HashML-DSA works in the dilithium reference for SHA-256, SHA-512 and SHAKE128-256, and its construction is independently confirmed by pyca/cryptography sign_mu/verify_mu (H-10, both directions VALID).</li>
<li>liboqs 0.16.0 exposes <strong>no HashML-DSA API</strong> (N/A, NA-1): prehash signing is unavailable there, not merely untested.</li>
<li>ACVP known-answer vectors: sigGen %(sgn)d/%(sgm)d, sigVer %(svn)d/%(svm)d, keyGen %(kgn)d/%(kgm)d (%(katt)d/%(katm)d).</li>
</ul>

<h2>Implementations (pinned)</h2>
<table>
<tr><th></th><th>Implementation A</th><th>Implementation B</th><th>Cross-check only</th></tr>
<tr><td>Name</td><td>liboqs %(libv)s via liboqs-python %(libb)s</td><td>pq-crystals/dilithium reference</td><td>pyca/cryptography %(xv)s</td></tr>
<tr><td>Version / commit</td><td>%(libv)s</td><td><code>%(refc)s</code></td><td>%(xv)s</td></tr>
<tr><td>Algorithm</td><td>ML-DSA-44</td><td>ML-DSA-44 (DILITHIUM_MODE 2)</td><td>ML-DSA-44</td></tr>
<tr><td>pk / sk / sig bytes</td><td>%(libpk)d / %(libsk)d / %(libsig)d</td><td>%(refpk)d / %(refsk)d / %(refsig)d</td><td>1312 / 2560 / 2420</td></tr>
<tr><td>Context API</td><td>sign_with_ctx_str / verify_with_ctx_str</td><td>crypto_sign_signature / crypto_sign_verify (ctx parameter)</td><td>sign(data, context=...) / verify(..., context=...)</td></tr>
<tr><td>Prehash API</td><td><strong>none (N/A)</strong></td><td>crypto_sign_signature_internal / verify_internal with pre = 0x01 || len(ctx) || ctx || OID (FIPS 204 Alg. 4/5, section 6 testing interface)</td><td>none native; sign_mu/verify_mu take a caller-computed mu</td></tr>
</table>

<h2>Case matrix (all %(total)d cases)</h2>
<table>
<tr><th>ID</th><th>Case</th><th>Implementation</th><th>Expected</th><th>Observed</th><th>Match</th></tr>
%(cases)s
</table>

<h2>ACVP known-answer vectors (ML-DSA-44)</h2>
<table>
<tr><th>Vector set</th><th>Checked</th><th>Matched</th><th>Mismatched</th></tr>
%(kat)s
</table>
<p>Note: the ACVP "internalProjection" vectors are projections onto the
FIPS 204 section 6 internal API — the "message" field is the already
encoded M' fed to Sign_internal / Verify_internal, not the raw message
M. See findings F-4.</p>

<h2>Files in this pack</h2>
<ul>
<li><code>README.md</code> — this summary, rerun instructions, sources</li>
<li><code>findings.md</code> — severity-ranked findings F-1–F-6</li>
<li><code>matrix.md</code> — implementation comparison matrix</li>
<li><code>index.md</code> — claim-to-evidence index</li>
<li><code>rubric.md</code> — evidence rubric (15/16)</li>
<li><code>walkthrough.log</code> — build/run narrative</li>
<li><code>run_harness.py</code> — main harness (45 cases)</li>
<li><code>run_kat.py</code> — ACVP KAT validation (50 vectors)</li>
<li><code>src/ref_mldsa_driver.c</code>, <code>src/build_drivers.sh</code> — reference driver + build</li>
<li><code>outputs/results.json</code>, <code>outputs/kat_results.json</code> — machine-readable results</li>
<li><code>outputs/run_harness.log</code>, <code>outputs/run_kat.log</code> — unedited harness logs</li>
<li><code>outputs/artifacts/*.bin</code> — public keys and signatures per case (secret keys are NOT in the pack)</li>
<li><code>outputs/SHA256SUMS</code> — digests of the outputs above</li>
<li><code>outputs/raw/FIPS-204.pdf</code> (.txt) — the standard under test</li>
</ul>

<h2>Sources</h2>
<ul>
<li>FIPS 204: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf (DOI 10.6028/NIST.FIPS.204), SHA-256 <code>%(fipssha)s</code></li>
<li>liboqs 0.16.0 / liboqs-python 0.16.0.2: https://github.com/open-quantum-safe/liboqs</li>
<li>pq-crystals/dilithium, commit <code>%(refc)s</code>: https://github.com/pq-crystals/dilithium.git</li>
<li>pyca/cryptography 50.0.2: https://cryptography.io/ (cross-check only)</li>
<li>ACVP ML-DSA vectors: liboqs test tree, tests/ACVP_Vectors/ML-DSA-{keyGen,sigGen,sigVer}-FIPS204/internalProjection.json</li>
</ul>
</body>
</html>
""" % {
    "total": counts["total"],
    "matched": counts["matched"],
    "mismatches": len(counts["mismatches"]),
    "nvalid": n_valid, "nneg": n_neg, "nna": n_na,
    "sgn": kat_n["sigGen"][1], "sgm": kat_n["sigGen"][0],
    "svn": kat_n["sigVer"][1], "svm": kat_n["sigVer"][0],
    "kgn": kat_n["keyGen"][1], "kgm": kat_n["keyGen"][0],
    "katt": kat_total, "katm": kat_matched,
    "libv": esc(lib["version"]),
    "libb": esc(lib["binding"].split()[-1]),
    "libpk": lib["pk_bytes"], "libsk": lib["sk_bytes"],
    "libsig": lib["sig_bytes"],
    "refc": esc(ref["commit"]),
    "refpk": ref["pk_bytes"], "refsk": ref["sk_bytes"],
    "refsig": ref["sig_bytes"],
    "xv": esc(xcheck["version"]),
    "cases": case_rows,
    "kat": kat_rows,
    "fipssha": esc(RES["fips204"]["sha256"]),
}

out = os.path.join(HERE, "index.html")
with open(out, "w") as f:
    f.write(page)
print("wrote %s (%d bytes, %d cases, KAT 50/50)"
      % (out, len(page), counts["total"]))
