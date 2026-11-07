#!/usr/bin/env python3
"""ACVP known-answer validation for the dilithium reference driver.

Sources (copied from the liboqs test tree into src/acvp/; the liboqs
tree itself carries these files under tests/ACVP_Vectors/):
  - ML-DSA-sigGen-FIPS204.json: deterministic (rnd = {0}32, FIPS 204
    section 5.2) and hedged sigGen vectors. Only the deterministic
    ML-DSA-44 groups are checked here.
  - ML-DSA-sigVer-FIPS204.json: verify vectors (pk/sk at group level).
  - ML-DSA-keyGen-FIPS204.json: seed -> pk vectors.

IMPORTANT (established empirically, 2026-11-07): these
"internalProjection" vectors are projections onto the FIPS 204
section 6 INTERNAL API, not onto Algorithms 2/3. The "message" field
is the already-encoded M' fed to Sign_internal / Verify_internal:
signing the vector message with sign_det (Alg. 2, empty ctx) does NOT
reproduce the vector signature, while sign_internal with an EMPTY
prefix and rnd = {0}32 reproduces it byte for byte (verified for
tc1 before adopting this reading). Likewise the sigVer vectors only
match under verify_internal with an empty prefix. Because of that,
the sigVer vectors cannot be checked through liboqs, whose API only
exposes Algorithms 2/3 (it always prepends 0x00 || len(ctx)); that
limitation is recorded, not worked around.

The vectors contain no context field and no preHash groups, so they
validate pure ML-DSA with the empty context only. Prehash validation
is H-10 in run_harness.py (two independent implementations agreeing
on the FIPS 204 Alg. 4/5 construction).

Usage: ./venv/bin/python run_kat.py
Exit 0 when every checked vector matches; 1 otherwise.
Writes outputs/kat_results.json.
"""
import hashlib
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "outputs")
DRIVER = os.path.join(HERE, "ref_mldsa_driver")
ACVP = os.path.join(HERE, "src", "acvp")


def w(path, data):
    with open(path, "wb") as f:
        f.write(data)


def run(cmd):
    p = subprocess.run(cmd, capture_output=True)
    return (p.returncode, p.stdout.decode(errors="replace"),
            p.stderr.decode(errors="replace"))


def main():
    os.makedirs(OUT, exist_ok=True)
    from cryptography.hazmat.primitives.asymmetric import mldsa

    results = {"sigGen": [], "sigVer": [], "keyGen": []}
    fails = []

    # ---- sigGen, deterministic ML-DSA-44 ----
    # "message" is M' (internal-API input): sign_internal, empty prefix,
    # rnd = {0}32, and the signature must equal the vector byte for byte.
    sg = json.load(open(os.path.join(ACVP, "ML-DSA-sigGen-FIPS204.json")))
    w(os.path.join(OUT, "empty_pre.bin"), b"")
    for g in sg["testGroups"]:
        if g["parameterSet"] != "ML-DSA-44" or not g["deterministic"]:
            continue
        for t in g["tests"]:
            sk = bytes.fromhex(t["sk"])
            msg = bytes.fromhex(t["message"])
            expect = bytes.fromhex(t["signature"])
            w(os.path.join(OUT, "kat_sk.bin"), sk)
            w(os.path.join(OUT, "kat_msg.bin"), msg)
            rc, out, err = run([DRIVER, "sign_internal",
                                os.path.join(OUT, "kat_sk.bin"),
                                os.path.join(OUT, "empty_pre.bin"),
                                os.path.join(OUT, "kat_msg.bin"),
                                os.path.join(OUT, "kat_sig.bin"), "zeros"])
            got = open(os.path.join(OUT, "kat_sig.bin"), "rb").read() \
                if rc == 0 else b""
            ok = (rc == 0 and got == expect)
            results["sigGen"].append(
                {"tgId": g["tgId"], "tcId": t["tcId"], "match": ok})
            print("sigGen tg%d tc%s: %s"
                  % (g["tgId"], t["tcId"], "MATCH" if ok else "MISMATCH"))
            if not ok:
                fails.append("sigGen tc%s" % t["tcId"])

    # ---- sigVer, ML-DSA-44 (verify_internal, empty prefix; pk/sk live
    # at group level). liboqs cannot check these vectors: its API only
    # exposes Algorithms 2/3 and always prepends 0x00 || len(ctx).
    sv = json.load(open(os.path.join(ACVP, "ML-DSA-sigVer-FIPS204.json")))
    for g in sv["testGroups"]:
        if g["parameterSet"] != "ML-DSA-44":
            continue
        pk = bytes.fromhex(g["pk"])
        w(os.path.join(OUT, "kat_pk.bin"), pk)
        for t in g["tests"]:
            msg = bytes.fromhex(t["message"])
            s = bytes.fromhex(t["signature"])
            expect = bool(t["testPassed"])
            w(os.path.join(OUT, "kat_msg.bin"), msg)
            w(os.path.join(OUT, "kat_sig.bin"), s)
            rc, out, err = run([DRIVER, "verify_internal",
                                os.path.join(OUT, "kat_pk.bin"),
                                os.path.join(OUT, "empty_pre.bin"),
                                os.path.join(OUT, "kat_msg.bin"),
                                os.path.join(OUT, "kat_sig.bin")])
            ref_ok = (rc == 0)
            ok = (ref_ok == expect)
            results["sigVer"].append(
                {"tgId": g["tgId"], "tcId": t["tcId"],
                 "testPassed": expect, "ref": ref_ok,
                 "liboqs": "N/A (vector message is internal-API M')",
                 "match": ok})
            print("sigVer tg%d tc%s: expected=%s ref=%s %s"
                  % (g["tgId"], t["tcId"], expect, ref_ok,
                     "MATCH" if ok else "MISMATCH"))
            if not ok:
                fails.append("sigVer tc%s" % t["tcId"])

    # ---- keyGen, ML-DSA-44: seed -> pk via cryptography ----
    kg = json.load(open(os.path.join(ACVP, "ML-DSA-keyGen-FIPS204.json")))
    for g in kg["testGroups"]:
        if g["parameterSet"] != "ML-DSA-44":
            continue
        for t in g["tests"]:
            seed = bytes.fromhex(t["seed"])
            expect_pk = bytes.fromhex(t["pk"])
            got_pk = mldsa.MLDSA44PrivateKey.from_seed_bytes(seed) \
                .public_key().public_bytes_raw()
            ok = (got_pk == expect_pk)
            results["keyGen"].append(
                {"tgId": g["tgId"], "tcId": t["tcId"], "match": ok})
            print("keyGen tg%d tc%s: %s"
                  % (g["tgId"], t["tcId"], "MATCH" if ok else "MISMATCH"))
            if not ok:
                fails.append("keyGen tc%s" % t["tcId"])

    n = sum(len(v) for v in results.values())
    print("KAT vectors checked: %d, failures: %d" % (n, len(fails)))
    with open(os.path.join(OUT, "kat_results.json"), "w") as f:
        json.dump(results, f, indent=2)
    if fails:
        print("FAILURES:", ", ".join(fails))
        return 1
    print("RESULT: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
