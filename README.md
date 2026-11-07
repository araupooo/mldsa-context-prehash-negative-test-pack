# ML-DSA Context-String and HashML-DSA Prehash Negative-Test Pack

Reusable evidence pack checking ML-DSA context-string and HashML-DSA
handling in two pinned ML-DSA-44 implementations against the exact
FIPS 204 requirements.

## Headline results

- **Harness: 45 cases, 45 matched the expected outcome, 0 mismatches.**
  21 valid-agreement cases VALID as expected; 21 negative/error cases
  rejected or failed as expected; 2 N/A probes.
- **Context handling is fully conformant in both implementations.**
  Cross-verification liboqs ↔ dilithium reference is VALID in both
  directions with a non-empty context, and every wrong-context,
  overlong-context, altered-signature, message-mismatch and wrong-key
  negative is rejected as expected.
- **HashML-DSA works in the dilithium reference** for SHA-256, SHA-512
  and SHAKE128-256, and its construction is independently confirmed by
  pyca/cryptography `sign_mu`/`verify_mu` (H-10, both directions VALID).
- **liboqs 0.16.0 exposes no HashML-DSA API** (N/A, case NA-1): prehash
  signing is unavailable there, not merely untested.
- **ACVP known-answer vectors: 50/50** — sigGen 10/10, sigVer 15/15,
  keyGen 25/25 (ML-DSA-44).

## Implementations (pinned)

| | Implementation A | Implementation B | Cross-check only |
|---|---|---|---|
| Name | liboqs 0.16.0 via liboqs-python 0.16.0.2 | pq-crystals/dilithium reference | pyca/cryptography 50.0.2 |
| Commit | — (pip release) | `d35ba3fe5449bee3e6d43e1f296c3ca818bd36be` (2026-06-03) | — (pip release) |
| Algorithm | ML-DSA-44 | ML-DSA-44 (DILITHIUM_MODE 2) | ML-DSA-44 |
| pk / sk / sig bytes | 1312 / 2560 / 2420 | 1312 / 2560 / 2420 | 1312 / 2560 / 2420 |
| Context API | `sign_with_ctx_str` / `verify_with_ctx_str` | `crypto_sign_signature` / `crypto_sign_verify` (ctx parameter) | `sign(data, context=...)` / `verify(..., context=...)` |
| Prehash API | none (N/A) | `crypto_sign_signature_internal` / `crypto_sign_verify_internal` with `pre = 0x01 \|\| len(ctx) \|\| ctx \|\| OID` (FIPS 204 Alg. 4/5, section 6 testing interface) | none native; `sign_mu`/`verify_mu` take a caller-computed mu |

Sizes match FIPS 204 Table 2 exactly in every implementation
(ML-DSA-44: pk 1312, sk 2560, sig 2420). In this run, liboqs signing
took about 0.0003 s and reference hedged signing about 0.002 s per
signature (timings vary by run; see `outputs/run_harness.log`).

## What FIPS 204 requires (quoted, with section references)

- **Context string, at most 255 bytes.** Algorithm 2 (ML-DSA.Sign,
  §5.2): "context string ctx (a byte string of 255 or fewer bytes)";
  line 1–2: "if |ctx| > 255 then return ⊥". Algorithm 3
  (ML-DSA.Verify, §5.3) has the identical check. The encoded message
  is `M' = 0x00 || len(ctx) || ctx || M` (Alg. 2 line 10, Alg. 3
  line 5).
- **HashML-DSA (§5.4.1, Algorithms 4/5).** `M' = 0x01 || len(ctx) ||
  ctx || OID(PH) || PH(M)`; the domain separator is 1 for pre-hash
  signing. DER OIDs (Alg. 4): SHA-256 `06 09 60 86 48 01 65 03 04 02
  01` (2.16.840.1.101.3.4.2.1); SHA-512 `06 09 60 86 48 01 65 03 04
  02 03`; SHAKE128 `06 09 60 86 48 01 65 03 04 02 0B` (256-bit
  output). "The identifier for a signature ... should indicate
  whether the signature is a ML-DSA signature or a pre-hash
  HashML-DSA signature" and, for pre-hash, the hash function used
  (§5.4). "In general, the 'pure' ML-DSA version is preferred"
  (§5.4).
- **Internal functions (§6).** "The interfaces specified in this
  section will be used when testing of ML-DSA implementations is
  performed through the CAVP." They "should not be made available to
  applications" other than for testing. Algorithm 7
  (Sign_internal): `mu = H(tr || M', 64)` with H = SHAKE256.
- **Hedged vs deterministic (§5.2).** Hedged signing is the default
  (random `rnd` from an approved RBG); "for the optional
  deterministic variant, substitute rnd ← {0}32".

Full text: `outputs/raw/FIPS-204.pdf` (SHA-256
`57239b9f84c03227eda3ca0991204dc7764c79af9ce2e6824eda774918d46b6b`),
plain text `outputs/raw/FIPS-204.txt`.

## Case list (45 cases; every case matched its expected outcome)

Pure ML-DSA / context (C-01–C-14, both implementations unless noted):
valid agreement with empty context (C-01) and with context
`release-manifest-v1` (C-02); cross-verification in both directions
(C-03); 255-byte context boundary (C-04); 256-byte context refused on
sign (C-05, NA-2) and on verify (C-06, NA-3); wrong context (C-07);
altered signature, last byte flipped (C-08); message mismatch (C-09);
empty message with context (C-10); binary context containing NUL bytes
(C-11); 1-byte context (C-12); wrong key (C-13); cross-implementation
wrong context (C-14).

HashML-DSA (H-01–H-13, dilithium reference; liboqs N/A): SHA-256 with
empty context (H-01), SHA-512 with context (H-02), SHAKE128-256 with
context (H-03); prehash mismatch, sign SHA-256 / verify SHA-512 (H-04);
wrong OID, SHA-512 OID over a SHA-256 digest (H-05); message mismatch
(H-06); wrong context (H-07); 256-byte context refused at construction
(H-08); pure signature rejected as HashML-DSA and vice versa (H-09);
independent cross-check via cryptography `sign_mu`/`verify_mu` over
the same keypair and the same mu (H-10); SHA-256 over a 1 MiB message
(H-11); SHA-256 over the empty message (H-12); malformed prefix (length
byte 0 with a 256-byte context) silently accepted by the section 6
internal API (H-13 — documents a footgun, see finding F-3).

N/A probes: liboqs has no HashML-DSA algorithm or prehash method
(NA-1); cryptography has no native HashML-DSA API either, only
external-mu `sign_mu`/`verify_mu` (NA-5).

ACVP known-answer vectors (ML-DSA-44, `run_kat.py`): deterministic
sigGen 10/10 signatures reproduced byte for byte; sigVer 15/15
outcomes matched (3 valid, 12 invalid as labelled); keyGen 25/25
public keys derived from the vector seeds. Note the vectors are
projections onto the section 6 internal API — see finding F-4.

## Files in this pack

- `README.md` — this file
- `findings.md` — severity-ranked findings F-1–F-6
- `matrix.md` — implementation comparison matrix
- `index.md` — claim-to-evidence index
- `rubric.md` — evidence rubric (15/16)
- `index.html` — rendered self-contained page (generated from
  `outputs/results.json` by `src/render_index.py`)
- `walkthrough.log` — build/run narrative
- `run_harness.py` — main harness (45 cases)
- `run_kat.py` — ACVP KAT validation (50 vectors)
- `src/ref_mldsa_driver.c`, `src/build_drivers.sh` — reference driver
  and build (clone at the pinned commit if absent)
- `src/acvp/*.json` — ACVP ML-DSA vector files used (copied from the
  liboqs test tree)
- `src/render_index.py` — renders `index.html` from the result files
- `outputs/results.json`, `outputs/kat_results.json` — machine-readable
  results
- `outputs/run_harness.log`, `outputs/run_kat.log` — unedited logs
- `outputs/artifacts/*.bin` — public keys and signatures per case
  (secret keys are NOT in the pack; they live under `outputs/keys/` in
  the working directory only)
- `outputs/SHA256SUMS` — digests of the outputs above
- `outputs/raw/FIPS-204.pdf`, `outputs/raw/FIPS-204.txt` — the
  standard under test

## Rerun instructions

Environment used: Python 3.12.3, gcc 13.3.0, git 2.43.0. No
privileged access needed.

```bash
# 1. Create a venv and install the two Python libraries
python3 -m venv venv && source venv/bin/activate
pip install "liboqs-python==0.16.0.2" "cryptography==50.0.2"

# 2. One-command rerun (rebuilds the driver, runs the harness and the
#    KAT validation, re-renders index.html, regenerates SHA256SUMS)
bash run_all.sh
```

Expected: `run_harness.py` ends with `RESULT: OK` (45/45 cases) and
`run_kat.py` ends with `RESULT: OK` (50/50 vectors). Keypairs are
generated fresh on every run, so the artifact bytes differ between
runs; the case outcomes must be identical. Verify digests with
`(cd outputs && sha256sum -c SHA256SUMS)`.

## Re-verifying a signature from the pack alone

`outputs/artifacts/` holds the public key and signature for each
measured case. Example — the H-02 HashML-DSA SHA-512 signature
(`H-02_sig.bin`, context `release-manifest-v1`):

```python
import hashlib
# M' = 0x01 || len(ctx) || ctx || OID(SHA-512) || SHA512(message)
msg = b"ML-DSA context/prehash test message"
ctx = b"release-manifest-v1"
oid = bytes.fromhex("0609608648016503040203")
pre = b"\x01" + bytes([len(ctx)]) + ctx + oid
phm = hashlib.sha512(msg).digest()
# verify with the reference driver (rebuild per src/build_drivers.sh):
#   ./ref_mldsa_driver verify_internal outputs/artifacts/ref_pk.bin \
#       pre.bin phm.bin outputs/artifacts/H-02_sig.bin
# where pre.bin holds `pre` and phm.bin holds `phm`. Expected: VALID.
```

Or with liboqs-python, for a pure-context case (C-02, same message
and context):

```python
import oqs
s = oqs.Signature("ML-DSA-44")
pk = open("outputs/artifacts/liboqs_pk.bin", "rb").read()
sig = open("outputs/artifacts/C02_liboqs_sig.bin", "rb").read()
print(s.verify_with_ctx_str(b"ML-DSA context/prehash test message",
                            sig, b"release-manifest-v1", pk))  # True
```

## Sources

- FIPS 204: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf
  (DOI 10.6028/NIST.FIPS.204)
- liboqs 0.16.0: https://github.com/open-quantum-safe/liboqs
- pq-crystals/dilithium, commit
  `d35ba3fe5449bee3e6d43e1f296c3ca818bd36be`:
  https://github.com/pq-crystals/dilithium.git
- pyca/cryptography 50.0.2: https://cryptography.io/
- ACVP ML-DSA vectors: liboqs test tree,
  `tests/ACVP_Vectors/ML-DSA-{keyGen,sigGen,sigVer}-FIPS204/internalProjection.json`
