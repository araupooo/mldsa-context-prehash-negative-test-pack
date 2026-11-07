# Implementation Comparison Matrix — ML-DSA Context and Prehash

All rows are measured (45/45 harness cases matched their expected
outcome; `outputs/results.json`, `outputs/run_harness.log`), except
where marked specification-derived. Parameter set under test:
ML-DSA-44 in both implementations (FIPS 204 Table 2: pk 1312 B,
sk 2560 B, sig 2420 B).

## 1. Pinned implementations

| | A — liboqs | B — dilithium reference | Cross-check — cryptography |
|---|---|---|---|
| Version / commit | liboqs 0.16.0, liboqs-python 0.16.0.2 | pq-crystals/dilithium `d35ba3fe5449bee3e6d43e1f296c3ca818bd36be` (2026-06-03) | pyca/cryptography 50.0.2 |
| Algorithm | ML-DSA-44 | ML-DSA-44 (DILITHIUM_MODE 2) | ML-DSA-44 |
| pk / sk / sig bytes | 1312 / 2560 / 2420 | 1312 / 2560 / 2420 | 1312 / 2560 / 2420 |
| Signing mode in this pack | hedged (default) | hedged (default); deterministic (`rnd = {0}32`) for KAT/H-10b | hedged; external-mu for H-10 |
| Context API | `sign_with_ctx_str` / `verify_with_ctx_str` | `crypto_sign_signature` / `crypto_sign_verify` (ctx parameter) | `sign(data, context=...)` / `verify(..., context=...)` |
| Prehash API | **none** (N/A, NA-1) | `crypto_sign_signature_internal` / `crypto_sign_verify_internal` with caller-built `pre` (FIPS 204 §6 testing interface) | **none native** (N/A, NA-5); `sign_mu`/`verify_mu` take a caller-computed mu |

## 2. Pure ML-DSA context handling (FIPS 204 Algorithms 2/3, §5.2/§5.3)

| Case | liboqs | dilithium ref | Cross |
|---|---|---|---|
| Valid agreement, empty ctx (C-01) | VALID | VALID | — |
| Valid agreement, ctx `release-manifest-v1` (C-02) | VALID | VALID | — |
| Cross-verify, same ctx (C-03) | — | — | VALID both directions |
| 255-byte ctx boundary (C-04) | VALID | VALID | — |
| 256-byte ctx, sign (C-05 / NA-2) | ERROR (`RuntimeError`) | ERROR (exit 2, `context too long`) | — |
| 256-byte ctx, verify (C-06 / NA-3) | INVALID (`False`, no exception) | ERROR (exit 2, `context too long`) | — |
| Wrong ctx on verify (C-07) | INVALID | INVALID | — |
| Altered signature, last byte flipped (C-08) | INVALID | INVALID | — |
| Message mismatch (C-09) | INVALID | INVALID | — |
| Empty message with ctx (C-10) | VALID | VALID | — |
| Binary ctx with NUL bytes (C-11) | VALID | VALID | — |
| 1-byte ctx (C-12) | VALID | (not run; same code path as C-02/C-04) | — |
| Wrong key (C-13) | INVALID | INVALID | — |
| Cross-verify, wrong ctx (C-14) | — | — | INVALID |

## 3. HashML-DSA prehash handling (FIPS 204 Algorithms 4/5, §5.4.1)

| Case | liboqs | dilithium ref | cryptography cross-check |
|---|---|---|---|
| SHA-256, empty ctx (H-01) | N/A (no API) | VALID | — |
| SHA-512, ctx (H-02) | N/A | VALID | — |
| SHAKE128-256, ctx (H-03) | N/A | VALID | — |
| Prehash mismatch, sign SHA-256 / verify SHA-512 (H-04) | N/A | INVALID | — |
| Wrong OID, SHA-512 OID over SHA-256 digest (H-05) | N/A | INVALID | — |
| Message mismatch (H-06) | N/A | INVALID | — |
| Wrong ctx (H-07) | N/A | INVALID | — |
| 256-byte ctx refused at construction (H-08) | N/A | ERROR (wrapper refuses) | — |
| Pure sig as HashML-DSA / HashML-DSA sig as pure (H-09) | N/A | INVALID / INVALID | — |
| Independent agreement on the same mu (H-10) | — | VALID both directions | VALID both directions |
| SHA-256 over 1 MiB message (H-11) | N/A | VALID | — |
| SHA-256 over empty message (H-12) | N/A | VALID | — |
| Malformed prefix, len byte 0 + 256-byte ctx (H-13) | N/A | VALID (silently accepted by the internal API — see F-3) | — |

## 4. Error-reporting comparison (overlong context, 256 bytes)

| | sign | verify |
|---|---|---|
| liboqs | raises `RuntimeError: Can not sign message with context string` | returns `False`, no exception |
| dilithium ref | exits 2, `context too long: 256 bytes (max 255)` | exits 2, `context too long: 256 bytes (max 255)` |
| cryptography | raises `ValueError: Context must be at most 255 bytes` | raises `ValueError: Context must be at most 255 bytes` |
| FIPS 204 Alg. 2/3 | return ⊥ (error indication) | return ⊥ (error indication) |

All three reject the overlong context; they differ only in how the
error is reported. liboqs's verify path is the outlier (boolean
`False` instead of an exception) — see finding F-2.

## 5. Independent validation

| Check | Result |
|---|---|
| ACVP deterministic sigGen, ML-DSA-44 (10 cases) | 10/10 signatures reproduced byte for byte (ref, `sign_internal`, empty prefix, `rnd = {0}32`) |
| ACVP sigVer, ML-DSA-44 (15 cases) | 15/15 outcomes matched (3 valid, 12 invalid as labelled) |
| ACVP keyGen, ML-DSA-44 (25 cases) | 25/25 public keys derived from the vector seeds (cryptography `from_seed_bytes`) |
| HashML-DSA construction, two independent implementations (H-10) | ref signature verifies via cryptography `verify_mu`; cryptography `sign_mu` signature verifies via ref `verify_internal` |
| FIPS 204 Table 2 sizes | pk 1312 / sk 2560 / sig 2420 in every implementation |

## 6. What was NOT measured

- ML-DSA-65 / ML-DSA-87: only ML-DSA-44 was exercised. The context
  and prehash code paths are parameter-independent (same
  `crypto_sign_signature` / `sign_with_ctx_str` entry points, same
  M' construction), but the other parameter sets were not run.
- Hedged HashML-DSA cross-implementation agreement beyond H-10: the
  H-10 cross-check used one keypair (ACVP keyGen tgId 1 tcId 1) and
  one message/context pair.
- No HashML-DSA ACVP vectors exist in the vector files used (the
  files contain pure ML-DSA groups only, no preHash groups), so
  prehash validation rests on the two-implementation agreement in
  H-10 rather than on official vectors.
