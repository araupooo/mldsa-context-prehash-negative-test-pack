# Rubric — ML-DSA context and prehash negative-test pack

Source of expected behavior: FIPS 204, *Module-Lattice-Based Digital
Signature Standard* (NIST.FIPS.204, August 2024), file
`outputs/raw/FIPS-204.pdf` (SHA-256
`57239b9f84c03227eda3ca0991204dc7764c79af9ce2e6824eda774918d46b6b`),
plain text `outputs/raw/FIPS-204.txt`.

Parameter set under test: ML-DSA-44 (Table 2: pk 1312 bytes, sk 2560
bytes, sig 2420 bytes). Two pinned implementations: liboqs 0.16.0 via
liboqs-python 0.16.0.2, and the pq-crystals/dilithium reference,
commit `d35ba3fe5449bee3e6d43e1f296c3ca818bd36be`.

## The question

Do two pinned ML-DSA-44 implementations handle context strings and
HashML-DSA prehashing exactly as FIPS 204 requires — including the
negative and boundary cases (wrong context, overlong context, altered
signature, message/prehash mismatch, wrong OID, unsupported API
paths) — with every pass, failure, or N/A independently checkable?

## What FIPS 204 actually requires

### §5.2, Algorithm 2 — ML-DSA.Sign(sk, M, ctx)

> Input: "context string ctx (a byte string of 255 or fewer bytes)."
> "1: if |ctx| > 255 then 2: return ⊥ — return an error indication if
> the context string is too long"
> "10: M' ← BytesToBits(IntegerToBytes(0, 1) ∥ IntegerToBytes(|ctx|, 1)
> ∥ ctx) ∥ M"

### §5.3, Algorithm 3 — ML-DSA.Verify(pk, M, σ, ctx)

The same 255-byte check (lines 1–2) and the same `M'` construction
(line 5), then `ML-DSA.Verify_internal(pk, M', σ)`.

### §5.4.1, Algorithms 4/5 — HashML-DSA.Sign / Verify

> "M' ← BytesToBits(IntegerToBytes(1, 1) ∥ IntegerToBytes(|ctx|, 1)
> ∥ ctx ∥ OID ∥ PH(M))"
> "The domain separator has a value of one for 'pre-hash' signing."
> OIDs (DER): SHA-256 `06 09 60 86 48 01 65 03 04 02 01`
> (2.16.840.1.101.3.4.2.1); SHA-512 `... 02 03`; SHAKE128 `... 02 0B`
> (256-bit output). "In general, the 'pure' ML-DSA version is
> preferred."

### §6, Algorithm 7 — ML-DSA.Sign_internal

> "The interfaces specified in this section will be used when testing
> of ML-DSA implementations is performed through the CAVP." ... "Other
> than for testing purposes, the interfaces for key generation and
> signature generation specified in this section should not be made
> available to applications."
> `mu = H(tr || M', 64)` with H = SHAKE256; hedged by default,
> deterministic variant uses `rnd ← {0}32` (§5.2).

### What FIPS 204 does NOT require

- It does not require any implementation to expose HashML-DSA: §5.4
  presents it as a variant for modules whose platform cannot hash
  efficiently inside Sign_internal, and notes application-level
  hashing as an alternative. A library without a prehash API is
  therefore non-conformant with nothing — but the gap must be
  recorded as N/A, not silently skipped (finding F-1).
- It does not specify how a binding reports ⊥ (exception, boolean,
  exit code). All three error-reporting styles observed here reject
  the overlong context; only their channel differs (matrix §4).

## Scoring (2 points per criterion, 16 total)

| # | Criterion | Points | Basis |
|---|---|---|---|
| 1 | Implementations pinned with versions/commits, environment recorded | 2/2 | liboqs 0.16.0 / liboqs-python 0.16.0.2; dilithium ref `d35ba3fe`; cryptography 50.0.2 (cross-check); Python 3.12.3, gcc 13.3.0; `outputs/run_harness.log` environment section |
| 2 | FIPS 204 requirements quoted with section references | 2/2 | README "What FIPS 204 requires"; this rubric; `outputs/raw/FIPS-204.pdf` + `.txt` in the pack |
| 3 | Valid agreement cases (pure + prehash) | 1/2 | Pure: empty/1-byte/255-byte/binary contexts, cross-verification both directions (C-01–C-04, C-10–C-12). Prehash: SHA-256/SHA-512/SHAKE128, 1 MiB and empty messages (H-01–H-03, H-11, H-12). Docked 1: only ML-DSA-44 exercised; ML-DSA-65/87 not run |
| 4 | Negative and boundary cases | 2/2 | 21 negative/error cases, all as expected: wrong ctx, overlong ctx on sign and verify, altered signature, message mismatch, wrong key, prehash mismatch, wrong OID, pure/prehash confusion (C-05–C-09, C-13, C-14, H-04–H-09) |
| 5 | Unsupported paths labelled N/A with demonstrating output | 2/2 | NA-1 (liboqs, no HashML-DSA), NA-5 (cryptography, no native HashML-DSA); mechanism/method listings printed in the log; H-08/H-13 document the internal-API limitation |
| 6 | Clean-run harness: unedited logs, exit codes, dependency versions, one-command rerun | 2/2 | `run_all.sh` (build → harness → KAT → render → SHA256SUMS); `outputs/run_harness.log` and `outputs/run_kat.log` unedited; `outputs/SHA256SUMS` verifiable with `sha256sum -c` |
| 7 | Methodology, comparison matrix, severity-ranked findings, limitations, claim-to-evidence index | 2/2 | `matrix.md`, `findings.md` (F-1–F-6), `index.md` (M-1–M-14, S-1–S-8, U-1–U-6), `matrix.md` §6 limitations |
| 8 | Independent verification (cross-implementation + official vectors) | 2/2 | Cross-verification both directions (C-03); HashML-DSA agreement across two independent implementations (H-10); ACVP KAT 50/50 (sigGen 10/10, sigVer 15/15, keyGen 25/25) |

## Total: 15/16 — strong

The single deduction is scope, not correctness: only ML-DSA-44 was
exercised, so the pack cannot speak for ML-DSA-65/87 context and
prehash behavior from measurement (the code paths are
parameter-independent, but that is a specification-derived claim, not
a measured one). Everything the pack does claim is measured, and
every case (45/45) matched its expected outcome.
