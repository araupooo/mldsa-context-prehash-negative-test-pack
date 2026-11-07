# Claim-to-Evidence Index

Every material claim in this pack, its status, and where to check it.
Status: measured = produced by a script in this pack with an unedited
log; specification-derived = taken from a cited primary source without
a live run; unavailable = could not be measured, labelled as such.

## Measured claims

| # | Claim | Evidence |
|---|---|---|
| M-1 | Harness: 45 cases, 45 matched the expected outcome, 0 mismatches (21 VALID, 16 INVALID, 5 ERROR, 2 N/A, 1 MATCH) | `outputs/results.json` → `counts` and `cases`; `outputs/run_harness.log` |
| M-2 | Context handling fully conformant in both implementations; cross-verification VALID both directions with a non-empty context (C-03) and INVALID under a wrong context (C-14) | `outputs/results.json` → cases C-01–C-14; `outputs/run_harness.log`; `outputs/artifacts/C02_liboqs_sig.bin`, `C02_ref_sig.bin`, `liboqs_pk.bin`, `ref_pk.bin` |
| M-3 | 255-byte context is the boundary: signs and verifies in both implementations (C-04); 256-byte context is refused on sign (C-05, NA-2) and on verify (C-06, NA-3) | `outputs/results.json` → cases C-04, C-05, C-06, NA-2, NA-3; `outputs/run_harness.log` |
| M-4 | All pure-ML-DSA negatives rejected as expected: wrong context, altered signature, message mismatch, wrong key (C-07–C-09, C-13) | `outputs/results.json` → cases C-07–C-09, C-13; `outputs/artifacts/C08_ref_sig_bad.bin` (altered signature) |
| M-5 | HashML-DSA works in the dilithium reference for SHA-256, SHA-512 and SHAKE128-256, with and without context (H-01–H-03, H-11, H-12) | `outputs/results.json` → cases H-01–H-03, H-11, H-12; `outputs/artifacts/H-01_sig.bin`, `H-02_sig.bin`, `H-03_sig.bin`, `H-11_sig.bin`, `H-12_sig.bin` |
| M-6 | HashML-DSA negatives rejected as expected: prehash mismatch (H-04), wrong OID (H-05), message mismatch (H-06), wrong context (H-07), pure/prehash confusion both directions (H-09) | `outputs/results.json` → cases H-04–H-07, H-09; `outputs/run_harness.log` |
| M-7 | The HashML-DSA construction agrees across two independent implementations: ref signature verifies via cryptography `verify_mu`, and cryptography `sign_mu` signature verifies via ref `verify_internal` (H-10) | `outputs/results.json` → cases H-10a–H-10c; `outputs/artifacts/H10_ref_sig.bin`, `H10_crypto_sig.bin`, `acvp_pk.bin` |
| M-8 | liboqs 0.16.0 exposes no HashML-DSA API (NA-1); cryptography 50.0.2 exposes no native HashML-DSA API either (NA-5) | `outputs/run_harness.log` (mechanism list, method list); `outputs/results.json` → cases NA-1, NA-5 |
| M-9 | liboqs verify with a 256-byte context returns `False` without raising, while sign raises `RuntimeError` (NA-2, NA-3); cryptography raises `ValueError` on both paths (NA-4); the reference driver exits 2 with `context too long` on both (C-05, C-06) | `outputs/run_harness.log`; `outputs/results.json` → cases NA-2–NA-4, C-05, C-06 |
| M-10 | A malformed prehash prefix (length byte 0 with a 256-byte context) is silently accepted by the section 6 internal API (H-13) | `outputs/results.json` → case H-13; `outputs/artifacts/H13_sig.bin` |
| M-11 | ACVP vectors: sigGen 10/10, sigVer 15/15, keyGen 25/25 (50/50) | `outputs/kat_results.json`; `outputs/run_kat.log` |
| M-12 | Key/signature sizes match FIPS 204 Table 2 exactly in every implementation (pk 1312, sk 2560, sig 2420) | `outputs/results.json` → `implementations.*`; `outputs/run_harness.log` (environment section) |
| M-13 | Public keys and signatures in `outputs/artifacts/` re-verify from the pack alone (see README re-verification snippets) | `outputs/artifacts/*.bin`; README "Re-verifying a signature from the pack alone" |
| M-14 | The ACVP vector "message" is the already-encoded M' for the section 6 internal API, not the raw message M (first Alg. 2 reading gave 10/10 sigGen mismatches; the internal-API reading gives 10/10 matches) | `run_kat.py` (docstring); `walkthrough.log`; `outputs/run_kat.log` (corrected run) |

## Specification-derived claims

| # | Claim | Source |
|---|---|---|
| S-1 | Context string is at most 255 bytes; `\|ctx\| > 255` returns an error indication; `M' = 0x00 \|\| len(ctx) \|\| ctx \|\| M` | FIPS 204 Algorithms 2/3 (§§5.2, 5.3), local `outputs/raw/FIPS-204.pdf`, DOI 10.6028/NIST.FIPS.204 |
| S-2 | HashML-DSA: `M' = 0x01 \|\| len(ctx) \|\| ctx \|\| OID(PH) \|\| PH(M)`; DER OIDs for SHA-256 / SHA-512 / SHAKE128 as in Algorithms 4/5; pure ML-DSA is preferred in general | FIPS 204 §5.4.1, Algorithms 4/5 |
| S-3 | Section 6 internal interfaces are for CAVP testing and "should not be made available to applications" other than for testing; `mu = H(tr \|\| M', 64)`, H = SHAKE256 | FIPS 204 §6, Algorithm 7 |
| S-4 | Hedged signing is the default; deterministic variant uses `rnd = {0}32` | FIPS 204 §5.2 |
| S-5 | ML-DSA-44 sizes and security category (Table 2) | FIPS 204 §4, Table 2 |
| S-6 | liboqs 0.16.0 / liboqs-python 0.16.0.2: ML-DSA-44 claimed NIST level 2, `supports_context_signing` True, `is_extmu` False | liboqs 0.16.0 `Signature.details` (printed in `outputs/run_harness.log`) |
| S-7 | pq-crystals/dilithium reference commit `d35ba3fe` is the FIPS 204 reference; `ref/api.h` gives dilithium2 pk 1312 / sk 2560 / sig 2420 | https://github.com/pq-crystals/dilithium.git, commit `d35ba3fe5449bee3e6d43e1f296c3ca818bd36be` |
| S-8 | pyca/cryptography 50.0.2 `mldsa` module: `sign(data, context=...)`, `sign_mu(mu)`, no `sign_prehashed` | cryptography 50.0.2 installed package (inspected live; `outputs/run_harness.log`) |

## Unavailable claims (labelled, not inferred)

| # | Claim | Why unavailable |
|---|---|---|
| U-1 | HashML-DSA behaviour in liboqs | No HashML-DSA API exists in liboqs 0.16.0 (NA-1); there is nothing to run |
| U-2 | HashML-DSA behaviour in cryptography | No native HashML-DSA API exists in cryptography 50.0.2 (NA-5); only the external-mu cross-check (H-10) |
| U-3 | HashML-DSA ACVP vectors | The vector files used contain pure ML-DSA groups only, no preHash groups; prehash validation rests on the two-implementation agreement in H-10 |
| U-4 | ML-DSA-65 / ML-DSA-87 context and prehash behaviour | Only ML-DSA-44 was exercised; the code paths are parameter-independent but the other sets were not run |
| U-5 | sigVer vectors through liboqs | The vectors' "message" is an internal-API M', and liboqs only exposes Algorithms 2/3 (it always prepends `0x00 \|\| len(ctx)`); see F-4 |
| U-6 | A second native HashML-DSA implementation besides the dilithium reference | No other pinned implementation in this pack exposes a HashML-DSA entry point; the H-10 cross-check via external-mu is the substitute |
