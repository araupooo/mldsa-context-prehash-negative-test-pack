# Severity-Ranked Findings — ML-DSA Context and Prehash

Severity-ranked findings from the measured runs. "Measured" means
produced by a script in this pack with an unedited log in `outputs/`;
"specification-derived" means taken from a cited primary source
without a live run; "unavailable" means it could not be measured and
is labelled as such.

## F-1 — MEDIUM — liboqs 0.16.0 has no HashML-DSA API at all

**Measured.** `oqs.get_enabled_sig_mechanisms()` lists `ML-DSA-44`,
`ML-DSA-65`, `ML-DSA-87` and no `HashML-DSA` name; the `Signature`
object has no prehash method (only the `is_extmu` flag, False)
(`outputs/run_harness.log`, case NA-1). A caller that needs to sign a
large message with liboqs cannot use the FIPS 204 §5.4 pre-hash
variant; the only options are signing the raw message (which hashes it
inside ML-DSA.Sign_internal, step 6 of Alg. 7) or hashing at the
application level and signing the digest as a plain message — the
route FIPS 204 §5.4 itself describes for CMS-style use ("a digest of
the content may be computed, and that digest is signed along with
other attributes"). The application-level route is NOT HashML-DSA: it
carries no domain separator 1 and no hash OID, so its signatures are
indistinguishable from pure signatures over a 32-byte message and will
verify as pure ML-DSA (demonstrated in reverse by H-09b, where a
HashML-DSA signature is rejected as pure — the two encodings are
deliberately disjoint).

**Remediation.** Do not assume a library that offers ML-DSA also
offers HashML-DSA. If pre-hash signing is required, pin an
implementation that exposes it (the dilithium reference's section 6
internal API, or a library with a native prehash entry point), and
record which hash function and OID each signature uses, per FIPS 204
§5.4 ("The identifier for a signature ... should indicate whether
the signature is a ML-DSA signature or a pre-hash HashML-DSA
signature").

## F-2 — LOW — liboqs verify with an overlong context returns False instead of raising

**Measured.** `sign_with_ctx_str` with a 256-byte context raises
`RuntimeError: Can not sign message with context string` (NA-2), but
`verify_with_ctx_str` with a 256-byte context returns `False` with no
exception (NA-3). The outcome is safe — the signature is rejected —
and a follow-up probe confirmed there is no truncation: a signature
made under a 255-byte context does NOT verify under the same 255
bytes plus one extra byte. The asymmetry is a binding-level
ergonomics issue, not a security issue: sign and verify report the
same FIPS 204 Alg. 2/3 error indication (⊥) through different
channels (exception vs boolean), so a caller that treats "verify did
not raise" as "the inputs were well-formed" would misread the result.
For comparison, pyca/cryptography raises `ValueError: Context must be
at most 255 bytes` on both sign and verify (NA-4), and the reference
driver exits 2 with `context too long` on both (C-05, C-06).

**Remediation.** Treat a `False` from `verify_with_ctx_str` as
"invalid OR malformed input", and validate context length (≤255
bytes) in the caller before verifying, rather than relying on the
binding to raise.

## F-3 — LOW — The reference internal API performs no context-length check (malformed-prefix footgun)

**Measured.** The FIPS 204 §6 internal entry points take the prefix
`pre` as opaque bytes and check nothing about it. The conformant
construction refuses a 256-byte context in the wrapper (H-08:
`ValueError: context too long`), but a caller that builds the prefix
itself and truncates `len(ctx)` to one byte (256 → length byte 0)
gets a signature that verifies (H-13: VALID). The two sides agree on
the malformed encoding, so the failure is silent: the signature is
internally consistent but not a FIPS 204 Algorithm 4 signature, and
no conformant verifier would accept it (its length byte says 0 while
256 context bytes follow). This is exactly why FIPS 204 §6 says the
internal interfaces "should not be made available to applications" —
they are a testing interface, and the length check belongs in the
Algorithm 4/5 wrapper.

**Remediation.** Never expose `crypto_sign_signature_internal` /
`crypto_sign_verify_internal` as a HashML-DSA API. Wrap them in an
Algorithm 4/5 entry point that enforces `|ctx| ≤ 255` before building
`M'`, and test the wrapper — not just the internal function — with an
overlong context.

## F-4 — INFO — ACVP ML-DSA vectors are internal-API projections, not Algorithm 2/3 vectors

**Measured.** The liboqs `internalProjection.json` vectors for
ML-DSA-44 sigGen/sigVer cannot be read as Algorithm 2/3 test cases:
signing the vector "message" with `sign_det` (Alg. 2, empty context)
does NOT reproduce the vector signature, while `sign_internal` with
an empty prefix and `rnd = {0}32` reproduces it byte for byte (10/10
deterministic sigGen cases, `outputs/run_kat.log`). Likewise the
sigVer vectors only match under `verify_internal` with an empty
prefix (15/15); the public `verify` with an empty context rejects
the unmodified case. The "message" field is the already-encoded M'
fed to Sign_internal / Verify_internal. A first reading of the vectors
as raw messages produced 10/10 sigGen mismatches; the corrected
reading is documented in `run_kat.py` and in the walkthrough log
(the first run's log was overwritten by the corrected rerun; the
mismatch and its cause are recorded in `walkthrough.log`, not hidden).

**Remediation.** When consuming ACVP ML-DSA vectors, check whether
the projection is onto the internal API before treating "message" as
the Algorithm 2 message. The same caution applies to any CAVP-style
vector set whose file name says "internalProjection".

## F-5 — INFO — pyca/cryptography 50.0.2 also has no native HashML-DSA API

**Measured.** The `mldsa` module exposes `sign(data, context=...)`,
`verify(...)`, and the external-mu pair `sign_mu(mu)` /
`verify_mu(signature, mu)`; there is no `sign_prehashed` or
HashML-DSA entry point (NA-5). The external-mu API is usable as an
independent cross-check — this pack uses it in H-10 to confirm the
reference's HashML-DSA construction over the same keypair and the
same mu (mu computed per FIPS 204 Alg. 7: `mu = SHAKE256(tr || M',
64)`, `tr = SHAKE256(pk, 64)`) — but the caller must build M' and mu
itself, including the OID and the context-length byte, so the same
wrapper-discipline caveat as F-3 applies.

**Remediation.** Same as F-1/F-3: if HashML-DSA is needed from
cryptography, build a tested Algorithm 4/5 wrapper around `sign_mu` /
`verify_mu` (or wait for a native API), and cross-check it against a
second implementation the way H-10 does.

## F-6 — INFO — Context handling is fully conformant in both implementations

**Measured.** 45/45 harness cases matched their expected outcome.
Pure ML-DSA with empty, 1-byte, 255-byte, and binary (NUL-containing)
contexts signs and verifies in both implementations; the two
implementations cross-verify each other's signatures in both
directions under the same context (C-03) and reject cross-verification
under a wrong context (C-14); all 21 negative/error cases (wrong
context, overlong context on sign and verify, altered signature,
message mismatch, wrong key, prehash mismatch, wrong OID, pure/
prehash confusion) behave exactly as FIPS 204 Algorithms 2–5 require.
HashML-DSA agrees across two independent implementations (H-10), and
50/50 ACVP vectors match. No conformance defect was found in context
handling in either pinned implementation; the findings above are about
missing APIs (F-1, F-5) and error-reporting ergonomics (F-2, F-3),
not about incorrect signatures.
