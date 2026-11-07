#!/usr/bin/env python3
"""ML-DSA context-string and HashML-DSA prehash negative-test harness.

Tests ML-DSA-44 in TWO pinned implementations against FIPS 204:
  A. liboqs 0.16.0 via liboqs-python 0.16.0.2 (pure ML-DSA + context).
  B. pq-crystals/dilithium reference, commit
     d35ba3fe5449bee3e6d43e1f296c3ca818bd36be (pure + context + HashML-DSA
     via the FIPS 204 section 6 internal entry points).

A third library, pyca/cryptography 50.0.2, is used ONLY as an
independent cross-check for the HashML-DSA mu construction (H-10):
it exposes sign_mu/verify_mu (external-mu signing), which is not a
HashML-DSA API. It is not one of the two pinned implementations.

FIPS 204 references (local copy FIPS-204.pdf, DOI 10.6028/NIST.FIPS.204):
  Alg. 2 ML-DSA.Sign / Alg. 3 ML-DSA.Verify (section 5.2/5.3):
    ctx is "a byte string of 255 or fewer bytes"; |ctx| > 255 returns
    an error indication; M' = 0x00 || len(ctx) || ctx || M.
  Alg. 4 HashML-DSA.Sign / Alg. 5 HashML-DSA.Verify (section 5.4.1):
    M' = 0x01 || len(ctx) || ctx || OID(PH) || PH(M); OIDs (DER):
      SHA-256:   06 09 60 86 48 01 65 03 04 02 01 (2.16.840.1.101.3.4.2.1)
      SHA-512:   06 09 60 86 48 01 65 03 04 02 03 (2.16.840.1.101.3.4.2.3)
      SHAKE128:  06 09 60 86 48 01 65 03 04 02 0B (2.16.840.1.101.3.4.2.11,
                 256-bit output)
  Alg. 7 ML-DSA.Sign_internal: mu = H(tr || M', 64) with H = SHAKE256.

Usage (from the task work directory):
    ./venv/bin/python run_harness.py
Exit code 0 means the harness ran to completion and every case matched
its expected outcome; a mismatch is printed and exits 1. (The harness
itself passing does not mean every implementation passed: several
cases EXPECT an INVALID result or an error, and N/A probes record
missing APIs as findings, not failures.)
Outputs: outputs/results.json, outputs/artifacts/*.bin (public keys
and signatures only), outputs/keys/* (secret keys, working dir only,
never staged into pack/ or repo/).
"""
import hashlib
import json
import os
import platform
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "outputs")
ART = os.path.join(OUT, "artifacts")
KEYS = os.path.join(OUT, "keys")
DRIVER = os.path.join(HERE, "ref_mldsa_driver")
VENV_PY = sys.executable

MSG = b"ML-DSA context/prehash test message"
MSG2 = b"a different test message"
CTX = b"release-manifest-v1"
CTX_BIN = b"\x00\x01\x02binary\xff"
CTX_255 = b"y" * 255
CTX_256 = b"x" * 256

OIDS = {
    "SHA-256": bytes.fromhex("0609608648016503040201"),
    "SHA-512": bytes.fromhex("0609608648016503040203"),
    "SHAKE128": bytes.fromhex("060960864801650304020b"),
}


def ph(name, data):
    if name == "SHA-256":
        return hashlib.sha256(data).digest()
    if name == "SHA-512":
        return hashlib.sha512(data).digest()
    if name == "SHAKE128":
        return hashlib.shake_128(data).digest(32)
    raise ValueError(name)


def prehash_pre(ctx, ph_name):
    """FIPS 204 Alg. 4/5 prefix: 0x01 || len(ctx) || ctx || OID(PH)."""
    if len(ctx) > 255:
        raise ValueError("context too long: %d bytes (max 255)" % len(ctx))
    return b"\x01" + bytes([len(ctx)]) + ctx + OIDS[ph_name]


def mu_for(pk, mprime):
    """FIPS 204 Alg. 7: mu = H(tr || M', 64); tr = H(pk, 64), H=SHAKE256."""
    tr = hashlib.shake_256(pk).digest(64)
    return hashlib.shake_256(tr + mprime).digest(64)


def w(path, data):
    with open(path, "wb") as f:
        f.write(data)


def run(cmd):
    t0 = time.time()
    p = subprocess.run(cmd, capture_output=True)
    return p.returncode, p.stdout.decode(errors="replace"), \
        p.stderr.decode(errors="replace"), time.time() - t0


CASES = []
FAILURES = []


def case(cid, title, impl, expected, observed, detail=""):
    ok = (expected == observed)
    CASES.append({"id": cid, "title": title, "implementation": impl,
                  "expected": expected, "observed": observed,
                  "match": ok, "detail": detail})
    print("[%s] %-72s expected=%-28s observed=%-28s %s"
          % (cid, title, expected, observed, "OK" if ok else "MISMATCH"))
    if detail:
        print("        %s" % detail)
    if not ok:
        FAILURES.append(cid)
    return ok


def main():
    os.makedirs(ART, exist_ok=True)
    os.makedirs(KEYS, exist_ok=True)
    print("== environment ==")
    import oqs
    import cryptography
    print("python:", platform.python_version())
    print("liboqs-python: 0.16.0.2 (pip)")
    print("cryptography:", cryptography.__version__)
    print("oqs mechanisms (ML-DSA):",
          [a for a in oqs.get_enabled_sig_mechanisms() if "ML-DSA" in a])
    print("oqs mechanisms (Hash):",
          [a for a in oqs.get_enabled_sig_mechanisms() if "Hash" in a])
    rc, out, err, _ = run(["git", "-C", os.path.join(HERE, "src", "ref-mldsa"),
                          "rev-parse", "HEAD"])
    ref_commit = out.strip()
    print("dilithium ref commit:", ref_commit)
    fips_path = os.path.join(HERE, "outputs", "raw", "FIPS-204.pdf")
    if not os.path.exists(fips_path):
        fips_path = os.path.join(HERE, "FIPS-204.pdf")
    fips_sha = hashlib.sha256(open(fips_path, "rb").read()).hexdigest()
    print("FIPS-204.pdf sha256:", fips_sha)
    rc, out, err, _ = run(["gcc", "--version"])
    print("gcc:", out.splitlines()[0] if out else "?")

    # ---------- N/A probes: what the APIs do and do not expose ----------
    print("== N/A probes ==")
    sig = oqs.Signature("ML-DSA-44")
    print("liboqs details:", sig.details)
    print("liboqs prehash/mu methods:",
          [m for m in dir(sig) if "prehash" in m.lower()
           or "pre_hash" in m.lower() or "mu" in m.lower()])
    case("NA-1", "liboqs exposes no HashML-DSA algorithm or prehash API",
         "liboqs 0.16.0", "N/A",
         "N/A" if not [a for a in oqs.get_enabled_sig_mechanisms()
                       if "Hash" in a] else "HAS-API",
         "get_enabled_sig_mechanisms() lists no HashML-DSA name; "
         "Signature has no prehash method (only is_extmu=False).")
    pk_l = sig.generate_keypair()
    sk_l = sig.export_secret_key()
    w(os.path.join(KEYS, "liboqs_sk.bin"), sk_l)
    w(os.path.join(ART, "liboqs_pk.bin"), pk_l)
    print("liboqs keypair: pk %d B, sk %d B" % (len(pk_l), len(sk_l)))
    case("NA-2", "liboqs sign with 256-byte context fails",
         "liboqs 0.16.0", "ERROR",
         "ERROR" if _liboqs_sign_overlong(sig) else "SIGNED",
         "sign_with_ctx_str(msg, 256-byte ctx) raises RuntimeError "
         "'Can not sign message with context string'.")
    case("NA-3", "liboqs verify with 256-byte context returns False",
         "liboqs 0.16.0", "INVALID",
         "INVALID" if not _liboqs_verify_overlong(sig, pk_l) else "VALID",
         "verify_with_ctx_str(msg, sig, 256-byte ctx, pk) returns False "
         "(no exception); FIPS 204 Alg. 3 requires an error indication, "
         "and a boolean False is the binding's equivalent of it.")

    # cryptography (cross-check library only): overlong context behaviour
    from cryptography.hazmat.primitives.asymmetric import mldsa
    from cryptography.exceptions import InvalidSignature
    csk = mldsa.MLDSA44PrivateKey.generate()
    try:
        csk.sign(MSG, context=CTX_256)
        c_over = "SIGNED"
    except ValueError as e:
        c_over = "ERROR"
        print("cryptography sign 256B ctx raised ValueError:", e)
    case("NA-4", "cryptography sign with 256-byte context fails",
         "cryptography 50.0.2 (cross-check only)", "ERROR", c_over,
         "ValueError 'Context must be at most 255 bytes'.")
    print("cryptography ML-DSA methods:",
          [m for m in dir(mldsa.MLDSA44PrivateKey) if not m.startswith("_")])
    case("NA-5", "cryptography exposes no native HashML-DSA API "
         "(only external-mu sign_mu/verify_mu)",
         "cryptography 50.0.2 (cross-check only)", "N/A",
         "N/A" if not hasattr(mldsa.MLDSA44PrivateKey, "sign_prehashed")
         else "HAS-API",
         "sign_mu/verify_mu take a caller-computed mu; the caller must "
         "build M' per FIPS 204 Alg. 4/5 itself.")

    # ---------- reference keypair ----------
    rc, out, err, dt = run([DRIVER, "keypair",
                            os.path.join(ART, "ref_pk.bin"),
                            os.path.join(KEYS, "ref_sk.bin")])
    assert rc == 0, err
    print(out.strip())
    pk_r = open(os.path.join(ART, "ref_pk.bin"), "rb").read()
    sk_r = open(os.path.join(KEYS, "ref_sk.bin"), "rb").read()
    print("ref keypair: pk %d B, sk %d B" % (len(pk_r), len(sk_r)))

    w(os.path.join(OUT, "msg.bin"), MSG)
    w(os.path.join(OUT, "msg2.bin"), MSG2)

    def ref_sign(sk_path, msg_path, sig_path, ctx=None, det=False):
        cmd = [DRIVER, "sign_det" if det else "sign",
               sk_path, msg_path, sig_path]
        if ctx is not None:
            cp = os.path.join(OUT, "ctx.bin")
            w(cp, ctx)
            cmd.append(cp)
        return run(cmd)

    def ref_verify(pk_path, msg_path, sig_path, ctx=None):
        cmd = [DRIVER, "verify", pk_path, msg_path, sig_path]
        if ctx is not None:
            cp = os.path.join(OUT, "ctx.bin")
            w(cp, ctx)
            cmd.append(cp)
        rc, out, err, _ = run(cmd)
        return ("VALID" if rc == 0 else
                "INVALID" if rc == 1 else "ERROR"), out.strip(), err.strip()

    def liboqs_sign(msg, ctx):
        t0 = time.time()
        s = sig.sign_with_ctx_str(msg, ctx)
        return s, time.time() - t0

    def liboqs_verify(msg, s, ctx, pk):
        return sig.verify_with_ctx_str(msg, s, ctx, pk)

    # ---------- pure / context cases ----------
    print("== pure ML-DSA / context-string cases ==")
    # C-01 valid agreement, empty context, both implementations
    s_l, t = liboqs_sign(MSG, b"")
    w(os.path.join(ART, "C01_liboqs_sig.bin"), s_l)
    case("C-01", "valid agreement, empty ctx, liboqs self-verify",
         "liboqs 0.16.0", "VALID",
         "VALID" if liboqs_verify(MSG, s_l, b"", pk_l) else "INVALID",
         "sign_with_ctx_str %.4f s" % t)
    rc, out, err, t = ref_sign(os.path.join(KEYS, "ref_sk.bin"),
                               os.path.join(OUT, "msg.bin"),
                               os.path.join(ART, "C01_ref_sig.bin"))
    v, _, _ = ref_verify(os.path.join(ART, "ref_pk.bin"),
                         os.path.join(OUT, "msg.bin"),
                         os.path.join(ART, "C01_ref_sig.bin"))
    case("C-01b", "valid agreement, empty ctx, ref self-verify",
         "dilithium ref", "VALID", v, "hedged sign %.4f s" % t)

    # C-02 valid agreement, non-empty context
    s_l2, _ = liboqs_sign(MSG, CTX)
    w(os.path.join(ART, "C02_liboqs_sig.bin"), s_l2)
    case("C-02", "valid agreement, ctx 'release-manifest-v1', liboqs",
         "liboqs 0.16.0", "VALID",
         "VALID" if liboqs_verify(MSG, s_l2, CTX, pk_l) else "INVALID")
    rc, out, err, _ = ref_sign(os.path.join(KEYS, "ref_sk.bin"),
                               os.path.join(OUT, "msg.bin"),
                               os.path.join(ART, "C02_ref_sig.bin"), CTX)
    v, _, _ = ref_verify(os.path.join(ART, "ref_pk.bin"),
                         os.path.join(OUT, "msg.bin"),
                         os.path.join(ART, "C02_ref_sig.bin"), CTX)
    case("C-02b", "valid agreement, ctx 'release-manifest-v1', ref",
         "dilithium ref", "VALID", v)

    # C-03 cross-verification between implementations (same ctx)
    v_ref_of_liboqs, _, _ = ref_verify(
        os.path.join(ART, "liboqs_pk.bin"), os.path.join(OUT, "msg.bin"),
        os.path.join(ART, "C02_liboqs_sig.bin"), CTX)
    case("C-03", "cross-verify: liboqs signature verified by ref (ctx)",
         "liboqs -> ref", "VALID", v_ref_of_liboqs)
    case("C-03b", "cross-verify: ref signature verified by liboqs (ctx)",
         "ref -> liboqs", "VALID",
         "VALID" if liboqs_verify(
             MSG, open(os.path.join(ART, "C02_ref_sig.bin"), "rb").read(),
             CTX, pk_r) else "INVALID")

    # C-04 255-byte context boundary
    s_l4, _ = liboqs_sign(MSG, CTX_255)
    case("C-04", "255-byte context signs and verifies, liboqs",
         "liboqs 0.16.0", "VALID",
         "VALID" if liboqs_verify(MSG, s_l4, CTX_255, pk_l) else "INVALID")
    rc, out, err, _ = ref_sign(os.path.join(KEYS, "ref_sk.bin"),
                               os.path.join(OUT, "msg.bin"),
                               os.path.join(ART, "C04_ref_sig.bin"), CTX_255)
    v, _, _ = ref_verify(os.path.join(ART, "ref_pk.bin"),
                         os.path.join(OUT, "msg.bin"),
                         os.path.join(ART, "C04_ref_sig.bin"), CTX_255)
    case("C-04b", "255-byte context signs and verifies, ref",
         "dilithium ref", "VALID", v)

    # C-05 256-byte context on sign must fail
    rc, out, err, _ = ref_sign(os.path.join(KEYS, "ref_sk.bin"),
                               os.path.join(OUT, "msg.bin"),
                               os.path.join(ART, "C05_ref_sig.bin"), CTX_256)
    case("C-05", "256-byte context on sign fails, ref",
         "dilithium ref", "ERROR",
         "ERROR" if rc == 2 else "SIGNED", err.strip())
    # (liboqs 256-byte sign covered by NA-2.)

    # C-06 256-byte context on verify must fail / be invalid
    rc, out, err, _ = run([DRIVER, "verify",
                           os.path.join(ART, "ref_pk.bin"),
                           os.path.join(OUT, "msg.bin"),
                           os.path.join(ART, "C02_ref_sig.bin"),
                           _ctxfile(CTX_256)])
    case("C-06", "256-byte context on verify fails, ref",
         "dilithium ref", "ERROR",
         "ERROR" if rc == 2 else ("VALID" if rc == 0 else "INVALID"),
         err.strip())

    # C-07 wrong context on verify
    case("C-07", "wrong context on verify rejected, liboqs",
         "liboqs 0.16.0", "INVALID",
         "VALID" if liboqs_verify(MSG, s_l2, b"other-context", pk_l)
         else "INVALID")
    v, _, _ = ref_verify(os.path.join(ART, "ref_pk.bin"),
                         os.path.join(OUT, "msg.bin"),
                         os.path.join(ART, "C02_ref_sig.bin"), b"other-context")
    case("C-07b", "wrong context on verify rejected, ref",
         "dilithium ref", "INVALID", v)

    # C-08 altered signature
    bad = bytearray(s_l2)
    bad[-1] ^= 0x01
    case("C-08", "altered signature (last byte flipped) rejected, liboqs",
         "liboqs 0.16.0", "INVALID",
         "VALID" if liboqs_verify(MSG, bytes(bad), CTX, pk_l) else "INVALID")
    w(os.path.join(ART, "C08_ref_sig_bad.bin"),
      _flip_last(open(os.path.join(ART, "C02_ref_sig.bin"), "rb").read()))
    v, _, _ = ref_verify(os.path.join(ART, "ref_pk.bin"),
                         os.path.join(OUT, "msg.bin"),
                         os.path.join(ART, "C08_ref_sig_bad.bin"), CTX)
    case("C-08b", "altered signature (last byte flipped) rejected, ref",
         "dilithium ref", "INVALID", v)

    # C-09 message mismatch
    case("C-09", "message mismatch rejected, liboqs",
         "liboqs 0.16.0", "INVALID",
         "VALID" if liboqs_verify(MSG2, s_l2, CTX, pk_l) else "INVALID")
    v, _, _ = ref_verify(os.path.join(ART, "ref_pk.bin"),
                         os.path.join(OUT, "msg2.bin"),
                         os.path.join(ART, "C02_ref_sig.bin"), CTX)
    case("C-09b", "message mismatch rejected, ref",
         "dilithium ref", "INVALID", v)

    # C-10 empty message with non-empty context
    s_l10, _ = liboqs_sign(b"", CTX)
    case("C-10", "empty message with context signs/verifies, liboqs",
         "liboqs 0.16.0", "VALID",
         "VALID" if liboqs_verify(b"", s_l10, CTX, pk_l) else "INVALID")
    w(os.path.join(OUT, "empty.bin"), b"")
    rc, out, err, _ = ref_sign(os.path.join(KEYS, "ref_sk.bin"),
                               os.path.join(OUT, "empty.bin"),
                               os.path.join(ART, "C10_ref_sig.bin"), CTX)
    v, _, _ = ref_verify(os.path.join(ART, "ref_pk.bin"),
                         os.path.join(OUT, "empty.bin"),
                         os.path.join(ART, "C10_ref_sig.bin"), CTX)
    case("C-10b", "empty message with context signs/verifies, ref",
         "dilithium ref", "VALID", v)

    # C-11 binary context containing NUL bytes
    s_l11, _ = liboqs_sign(MSG, CTX_BIN)
    case("C-11", "binary context with NUL bytes, liboqs",
         "liboqs 0.16.0", "VALID",
         "VALID" if liboqs_verify(MSG, s_l11, CTX_BIN, pk_l) else "INVALID")
    rc, out, err, _ = ref_sign(os.path.join(KEYS, "ref_sk.bin"),
                               os.path.join(OUT, "msg.bin"),
                               os.path.join(ART, "C11_ref_sig.bin"), CTX_BIN)
    v, _, _ = ref_verify(os.path.join(ART, "ref_pk.bin"),
                         os.path.join(OUT, "msg.bin"),
                         os.path.join(ART, "C11_ref_sig.bin"), CTX_BIN)
    case("C-11b", "binary context with NUL bytes, ref",
         "dilithium ref", "VALID", v)

    # C-12 1-byte context
    s_l12, _ = liboqs_sign(MSG, b"Q")
    case("C-12", "1-byte context signs/verifies, liboqs",
         "liboqs 0.16.0", "VALID",
         "VALID" if liboqs_verify(MSG, s_l12, b"Q", pk_l) else "INVALID")

    # C-13 wrong key
    case("C-13", "signature verified under wrong key rejected, liboqs",
         "liboqs 0.16.0", "INVALID",
         "VALID" if liboqs_verify(MSG, s_l2, CTX, pk_r) else "INVALID")
    v, _, _ = ref_verify(os.path.join(ART, "liboqs_pk.bin"),
                         os.path.join(OUT, "msg.bin"),
                         os.path.join(ART, "C02_ref_sig.bin"), CTX)
    case("C-13b", "signature verified under wrong key rejected, ref",
         "dilithium ref", "INVALID", v)

    # C-14 cross-implementation wrong context
    v, _, _ = ref_verify(os.path.join(ART, "liboqs_pk.bin"),
                         os.path.join(OUT, "msg.bin"),
                         os.path.join(ART, "C02_liboqs_sig.bin"),
                         b"other-context")
    case("C-14", "cross-verify with wrong context rejected (liboqs->ref)",
         "liboqs -> ref", "INVALID", v)

    # ---------- HashML-DSA cases (reference driver; liboqs N/A) ----------
    print("== HashML-DSA prehash cases (dilithium ref) ==")

    def ph_sign_verify(cid, title, ph_name, ctx, msg, msg_verify=None,
                       oid_name=None, det=False, expect="VALID"):
        """Sign PH(msg) with pre=(1,ctx,OID) and verify the same way."""
        pre = prehash_pre(ctx, oid_name or ph_name)
        w(os.path.join(OUT, "pre.bin"), pre)
        w(os.path.join(OUT, "phm.bin"), ph(ph_name, msg))
        cmd = [DRIVER, "sign_internal", os.path.join(KEYS, "ref_sk.bin"),
               os.path.join(OUT, "pre.bin"), os.path.join(OUT, "phm.bin"),
               os.path.join(ART, "%s_sig.bin" % cid)]
        if det:
            cmd.append("zeros")
        rc, out, err, t = run(cmd)
        if rc != 0:
            case(cid, title + " [sign]", "dilithium ref", expect,
                 "ERROR", err.strip())
            return None
        vmsg = msg_verify if msg_verify is not None else msg
        w(os.path.join(OUT, "phm_v.bin"), ph(ph_name, vmsg))
        rc, out, err, _ = run([DRIVER, "verify_internal",
                               os.path.join(ART, "ref_pk.bin"),
                               os.path.join(OUT, "pre.bin"),
                               os.path.join(OUT, "phm_v.bin"),
                               os.path.join(ART, "%s_sig.bin" % cid)])
        case(cid, title, "dilithium ref", expect,
             "VALID" if rc == 0 else ("INVALID" if rc == 1 else "ERROR"),
             "sign %.4f s; pre=%d B, PH(M)=%d B"
             % (t, len(pre), len(ph(ph_name, msg))))
        return os.path.join(ART, "%s_sig.bin" % cid)

    ph_sign_verify("H-01", "HashML-DSA SHA-256, empty ctx", "SHA-256", b"", MSG)
    ph_sign_verify("H-02", "HashML-DSA SHA-512, ctx 'release-manifest-v1'",
                   "SHA-512", CTX, MSG)
    ph_sign_verify("H-03", "HashML-DSA SHAKE128-256, ctx", "SHAKE128", CTX, MSG)
    # H-04 prehash mismatch: sign SHA-256, verify with SHA-512 PH
    pre = prehash_pre(b"", "SHA-256")
    w(os.path.join(OUT, "pre.bin"), pre)
    w(os.path.join(OUT, "phm.bin"), ph("SHA-256", MSG))
    rc, out, err, _ = run([DRIVER, "sign_internal",
                           os.path.join(KEYS, "ref_sk.bin"),
                           os.path.join(OUT, "pre.bin"),
                           os.path.join(OUT, "phm.bin"),
                           os.path.join(ART, "H04_sig.bin")])
    assert rc == 0, err
    w(os.path.join(OUT, "phm_v.bin"), ph("SHA-512", MSG))
    rc, out, err, _ = run([DRIVER, "verify_internal",
                           os.path.join(ART, "ref_pk.bin"),
                           os.path.join(OUT, "pre.bin"),
                           os.path.join(OUT, "phm_v.bin"),
                           os.path.join(ART, "H04_sig.bin")])
    case("H-04", "prehash mismatch (sign SHA-256, verify SHA-512) rejected",
         "dilithium ref", "INVALID",
         "VALID" if rc == 0 else ("INVALID" if rc == 1 else "ERROR"))
    # H-05 wrong OID: same digest, wrong OID in the verify prefix
    pre_wrong_oid = prehash_pre(b"", "SHA-512")
    w(os.path.join(OUT, "pre_wrong.bin"), pre_wrong_oid)
    rc, out, err, _ = run([DRIVER, "verify_internal",
                           os.path.join(ART, "ref_pk.bin"),
                           os.path.join(OUT, "pre_wrong.bin"),
                           os.path.join(OUT, "phm.bin"),
                           os.path.join(ART, "H04_sig.bin")])
    case("H-05", "wrong OID (SHA-512 OID over SHA-256 digest) rejected",
         "dilithium ref", "INVALID",
         "VALID" if rc == 0 else ("INVALID" if rc == 1 else "ERROR"))
    # H-06 message mismatch under prehash
    ph_sign_verify("H-06", "HashML-DSA message mismatch rejected",
                   "SHA-256", CTX, MSG, msg_verify=MSG2, expect="INVALID")
    # H-07 wrong context under prehash
    pre_ok = prehash_pre(CTX, "SHA-256")
    pre_bad = prehash_pre(b"other-context", "SHA-256")
    w(os.path.join(OUT, "pre.bin"), pre_ok)
    w(os.path.join(OUT, "phm.bin"), ph("SHA-256", MSG))
    rc, out, err, _ = run([DRIVER, "sign_internal",
                           os.path.join(KEYS, "ref_sk.bin"),
                           os.path.join(OUT, "pre.bin"),
                           os.path.join(OUT, "phm.bin"),
                           os.path.join(ART, "H07_sig.bin")])
    assert rc == 0, err
    w(os.path.join(OUT, "pre_bad.bin"), pre_bad)
    rc, out, err, _ = run([DRIVER, "verify_internal",
                           os.path.join(ART, "ref_pk.bin"),
                           os.path.join(OUT, "pre_bad.bin"),
                           os.path.join(OUT, "phm.bin"),
                           os.path.join(ART, "H07_sig.bin")])
    case("H-07", "HashML-DSA wrong context rejected",
         "dilithium ref", "INVALID",
         "VALID" if rc == 0 else ("INVALID" if rc == 1 else "ERROR"))
    # H-08 overlong context on HashML-DSA construction is refused
    try:
        prehash_pre(CTX_256, "SHA-256")
        case("H-08", "256-byte context refused at HashML-DSA construction",
             "dilithium ref", "ERROR", "CONSTRUCTED",
             "prehash_pre() did not refuse the overlong context")
    except ValueError as e:
        case("H-08", "256-byte context refused at HashML-DSA construction",
             "dilithium ref", "ERROR", "ERROR", str(e) + " (FIPS 204 "
             "Alg. 4 lines 1-3; the ref internal API performs no length "
             "check itself -- it is the section 6 testing interface).")
    # H-09 pure/prehash confusion
    rc, out, err, _ = run([DRIVER, "verify_internal",
                           os.path.join(ART, "ref_pk.bin"),
                           os.path.join(OUT, "pre.bin"),
                           os.path.join(OUT, "phm.bin"),
                           os.path.join(ART, "C02_ref_sig.bin")])
    case("H-09", "pure ML-DSA signature rejected as HashML-DSA",
         "dilithium ref", "INVALID",
         "VALID" if rc == 0 else ("INVALID" if rc == 1 else "ERROR"))
    v, _, _ = ref_verify(os.path.join(ART, "ref_pk.bin"),
                         os.path.join(OUT, "phm.bin"),
                         os.path.join(ART, "H07_sig.bin"))
    case("H-09b", "HashML-DSA signature rejected as pure ML-DSA",
         "dilithium ref", "INVALID", v)
    # H-11 large message (1 MiB) prehash
    big = b"ABCD" * 262144
    assert len(big) == 1048576
    ph_sign_verify("H-11", "HashML-DSA SHA-256 over 1 MiB message",
                   "SHA-256", CTX, big)
    # H-12 SHA-256 of the empty message
    ph_sign_verify("H-12", "HashML-DSA SHA-256 over empty message",
                   "SHA-256", b"", b"")
    # H-13 malformed-prefix footgun: the section 6 internal API performs
    # NO context-length check. A caller that builds the prefix itself
    # and truncates len(ctx) mod 256 (256 -> length byte 0) gets a
    # signature that verifies -- silently non-conformant M'. This case
    # documents the behaviour; the conformant construction refuses the
    # overlong context at H-08. It is NOT a failure of the reference
    # implementation (the internal API is a testing interface, FIPS 204
    # section 6: "should not be made available to applications").
    bad_pre = b"\x01\x00" + CTX_256 + OIDS["SHA-256"]
    w(os.path.join(OUT, "pre_badlen.bin"), bad_pre)
    w(os.path.join(OUT, "phm.bin"), ph("SHA-256", MSG))
    rc, out, err, _ = run([DRIVER, "sign_internal",
                           os.path.join(KEYS, "ref_sk.bin"),
                           os.path.join(OUT, "pre_badlen.bin"),
                           os.path.join(OUT, "phm.bin"),
                           os.path.join(ART, "H13_sig.bin")])
    assert rc == 0, err
    rc, out, err, _ = run([DRIVER, "verify_internal",
                           os.path.join(ART, "ref_pk.bin"),
                           os.path.join(OUT, "pre_badlen.bin"),
                           os.path.join(OUT, "phm.bin"),
                           os.path.join(ART, "H13_sig.bin")])
    case("H-13", "malformed prefix (len byte 0, 256-byte ctx) is silently "
         "accepted by the internal API", "dilithium ref", "VALID",
         "VALID" if rc == 0 else ("INVALID" if rc == 1 else "ERROR"),
         "sign_internal/verify_internal perform no length check; the "
         "Alg. 4 check must live in the caller's wrapper (see H-08).")

    # H-10 cross-check with cryptography sign_mu/verify_mu (independent
    # implementation of the same mu construction, same keypair via an
    # ACVP keyGen vector seed).
    print("== H-10 cross-check (cryptography sign_mu) ==")
    import json as _json
    kg = _json.load(open(os.path.join(HERE, "src", "acvp",
                                      "ML-DSA-keyGen-FIPS204.json")))
    vec = kg["testGroups"][0]["tests"][0]
    seed = bytes.fromhex(vec["seed"])
    vec_pk = bytes.fromhex(vec["pk"])
    vec_sk = bytes.fromhex(vec["sk"])
    ck = mldsa.MLDSA44PrivateKey.from_seed_bytes(seed)
    ck_pk = ck.public_key().public_bytes_raw()
    case("H-10a", "ACVP keyGen vector: cryptography seed derives the "
         "vector public key", "cryptography 50.0.2 (cross-check only)",
         "MATCH", "MATCH" if ck_pk == vec_pk else "MISMATCH",
         "ACVP keyGen tgId 1 tcId %s; pk sha256 %s"
         % (vec["tcId"], hashlib.sha256(vec_pk).hexdigest()[:16]))
    w(os.path.join(KEYS, "acvp_sk.bin"), vec_sk)
    w(os.path.join(ART, "acvp_pk.bin"), vec_pk)
    pre = prehash_pre(CTX, "SHA-256")
    phm = ph("SHA-256", MSG)
    mprime = pre + phm
    mu = mu_for(vec_pk, mprime)
    w(os.path.join(OUT, "pre.bin"), pre)
    w(os.path.join(OUT, "phm.bin"), phm)
    rc, out, err, _ = run([DRIVER, "sign_internal",
                           os.path.join(KEYS, "acvp_sk.bin"),
                           os.path.join(OUT, "pre.bin"),
                           os.path.join(OUT, "phm.bin"),
                           os.path.join(ART, "H10_ref_sig.bin"), "zeros"])
    assert rc == 0, err
    try:
        ck.public_key().verify_mu(
            open(os.path.join(ART, "H10_ref_sig.bin"), "rb").read(), mu)
        h10a = "VALID"
    except InvalidSignature:
        h10a = "INVALID"
    case("H-10b", "ref HashML-DSA signature verifies via cryptography "
         "verify_mu (same mu)", "ref -> cryptography", "VALID", h10a,
         "deterministic (rnd=0) ref signature over the ACVP keypair.")
    sig_mu = ck.sign_mu(mu)
    w(os.path.join(ART, "H10_crypto_sig.bin"), sig_mu)
    rc, out, err, _ = run([DRIVER, "verify_internal",
                           os.path.join(ART, "acvp_pk.bin"),
                           os.path.join(OUT, "pre.bin"),
                           os.path.join(OUT, "phm.bin"),
                           os.path.join(ART, "H10_crypto_sig.bin")])
    case("H-10c", "cryptography sign_mu signature verifies via ref "
         "verify_internal", "cryptography -> ref", "VALID",
         "VALID" if rc == 0 else ("INVALID" if rc == 1 else "ERROR"))

    # ---------- summary ----------
    print("== summary ==")
    n = len(CASES)
    matched = sum(1 for c in CASES if c["match"])
    print("cases: %d, matched expected outcome: %d, mismatches: %d"
          % (n, matched, len(FAILURES)))
    results = {
        "fips204": {"source": "https://nvlpubs.nist.gov/nistpubs/FIPS/"
                    "NIST.FIPS.204.pdf",
                    "doi": "10.6028/NIST.FIPS.204",
                    "sha256": fips_sha},
        "implementations": {
            "liboqs": {"name": "liboqs", "version": "0.16.0",
                       "binding": "liboqs-python 0.16.0.2",
                       "algorithm": "ML-DSA-44",
                       "pk_bytes": len(pk_l), "sk_bytes": len(sk_l),
                       "sig_bytes": 2420,
                       "context_api": "sign_with_ctx_str / "
                       "verify_with_ctx_str",
                       "prehash_api": None},
            "dilithium_ref": {"name": "pq-crystals/dilithium reference",
                              "commit": ref_commit,
                              "algorithm": "ML-DSA-44 (DILITHIUM_MODE 2)",
                              "pk_bytes": len(pk_r), "sk_bytes": len(sk_r),
                              "sig_bytes": 2420,
                              "context_api": "crypto_sign_signature / "
                              "crypto_sign_verify (ctx parameter)",
                              "prehash_api": "crypto_sign_signature_internal / "
                              "crypto_sign_verify_internal with "
                              "pre = 0x01||len(ctx)||ctx||OID (FIPS 204 "
                              "Alg. 4/5, section 6 testing interface)"},
            "cryptography_crosscheck": {
                "name": "pyca/cryptography", "version": "50.0.2",
                "role": "independent cross-check only (H-10)",
                "algorithm": "ML-DSA-44",
                "context_api": "sign(data, context=...) / "
                "verify(signature, data, context=...)",
                "prehash_api": "none native; sign_mu/verify_mu take a "
                "caller-computed mu"}},
        "cases": CASES,
        "counts": {"total": n, "matched": matched,
                   "mismatches": FAILURES},
    }
    with open(os.path.join(OUT, "results.json"), "w") as f:
        json.dump(results, f, indent=2)
    print("wrote outputs/results.json")
    if FAILURES:
        print("MISMATCHED CASES:", ", ".join(FAILURES))
        return 1
    print("RESULT: OK")
    return 0


def _liboqs_sign_overlong(sig):
    try:
        sig.sign_with_ctx_str(MSG, CTX_256)
        return False
    except Exception as e:
        print("liboqs sign 256B ctx raised:", type(e).__name__, str(e)[:120])
        return True


def _liboqs_verify_overlong(sig, pk):
    try:
        return sig.verify_with_ctx_str(MSG, sig.sign_with_ctx_str(MSG, CTX),
                                       CTX_256, pk)
    except Exception as e:
        print("liboqs verify 256B ctx raised:", type(e).__name__, str(e)[:120])
        return False


def _ctxfile(ctx):
    p = os.path.join(OUT, "ctx.bin")
    w(p, ctx)
    return p


def _flip_last(data):
    b = bytearray(data)
    b[-1] ^= 0x01
    return bytes(b)


if __name__ == "__main__":
    sys.exit(main())
