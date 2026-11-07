/* Driver for the pq-crystals/dilithium reference implementation
 * (FIPS 204 ML-DSA-44, DILITHIUM_MODE 2, commit d35ba3fe).
 *
 * Pure ML-DSA (FIPS 204 Algorithms 2/3) via the public
 * crypto_sign_signature / crypto_sign_verify entry points, which take
 * an explicit context string and return -1 when |ctx| > 255.
 *
 * HashML-DSA (FIPS 204 Algorithms 4/5) via the internal entry points
 * crypto_sign_signature_internal / crypto_sign_verify_internal
 * (FIPS 204 section 6: "The interfaces specified in this section will
 * be used when testing of ML-DSA implementations is performed").
 * The caller supplies the pre-hash prefix
 *   pre = 0x01 || len(ctx) || ctx || OID(PH)
 * and the pre-hashed message PH(M) as the message; the driver performs
 * exactly ML-DSA.Sign_internal / Verify_internal over M' = pre || PH(M).
 * The OID and PH(M) construction lives in the Python harness
 * (run_harness.py), where it is auditable against FIPS 204 Alg. 4/5.
 *
 * Deterministic signing (FIPS 204 section 5.2: "for the optional
 * deterministic variant, substitute rnd <- {0}32") is available via
 * sign_det / sign_internal with rnd file "zeros"; hedged signing uses
 * randombytes() from the reference tree.
 *
 * CLI (exit codes: 0 = ok / VALID, 1 = INVALID, 2 = error):
 *   keypair <pk_out> <sk_out>
 *   sign    <sk> <msg> <sig> [ctxfile]            (hedged, Alg. 2)
 *   sign_det <sk> <msg> <sig> [ctxfile]           (deterministic, rnd=0)
 *   verify  <pk> <msg> <sig> [ctxfile>            (Alg. 3)
 *   sign_internal <sk> <prefile> <msg> <sig> [rndfile|zeros]
 *   verify_internal <pk> <prefile> <msg> <sig>
 * A ctx file longer than 255 bytes makes sign/sign_det/verify exit 2
 * with "context too long" on stderr (the Alg. 2/3 error indication).
 * verify_internal prints VALID/INVALID and exits 0/1.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "api.h"
#include "sign.h"
#include "randombytes.h"

static uint8_t *read_file(const char *path, size_t *len) {
    FILE *f = fopen(path, "rb");
    if (!f) { fprintf(stderr, "cannot open %s\n", path); return NULL; }
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (n < 0) { fclose(f); return NULL; }
    uint8_t *buf = malloc((size_t)n ? (size_t)n : 1);
    if (n > 0 && fread(buf, 1, (size_t)n, f) != (size_t)n) {
        fclose(f); free(buf); return NULL;
    }
    fclose(f);
    *len = (size_t)n;
    return buf;
}

static int write_file(const char *path, const uint8_t *buf, size_t len) {
    FILE *f = fopen(path, "wb");
    if (!f) { fprintf(stderr, "cannot write %s\n", path); return -1; }
    if (len > 0 && fwrite(buf, 1, len, f) != len) { fclose(f); return -1; }
    fclose(f);
    return 0;
}

/* Read an optional context file. Returns 0 ok, 2 error (incl. >255). */
static int read_ctx(const char *path, uint8_t *ctx, size_t *ctxlen) {
    if (!path) { *ctxlen = 0; return 0; }
    size_t n = 0;
    uint8_t *b = read_file(path, &n);
    if (!b) return 2;
    if (n > 255) {
        fprintf(stderr, "context too long: %zu bytes (max 255)\n", n);
        free(b);
        return 2;
    }
    memcpy(ctx, b, n);
    *ctxlen = n;
    free(b);
    return 0;
}

static int do_keypair(const char *pk_out, const char *sk_out) {
    uint8_t pk[pqcrystals_dilithium2_PUBLICKEYBYTES];
    uint8_t sk[pqcrystals_dilithium2_SECRETKEYBYTES];
    if (pqcrystals_dilithium2_ref_keypair(pk, sk)) {
        fprintf(stderr, "keypair failed\n"); return 2;
    }
    if (write_file(pk_out, pk, sizeof pk) ||
        write_file(sk_out, sk, sizeof sk)) return 2;
    printf("keypair: pk %zu B, sk %zu B\n", sizeof pk, sizeof sk);
    return 0;
}

static int do_sign(const char *sk_in, const char *msg_in, const char *sig_out,
                   const char *ctxfile, int deterministic) {
    size_t sklen, mlen;
    uint8_t *sk = read_file(sk_in, &sklen);
    uint8_t *m = read_file(msg_in, &mlen);
    if (!sk || !m) return 2;
    if (sklen != pqcrystals_dilithium2_SECRETKEYBYTES) {
        fprintf(stderr, "bad sk length %zu\n", sklen); return 2;
    }
    uint8_t ctx[256];
    size_t ctxlen = 0;
    if (read_ctx(ctxfile, ctx, &ctxlen)) return 2;
    uint8_t sig[pqcrystals_dilithium2_BYTES];
    size_t siglen = 0;
    int r;
    if (deterministic) {
        uint8_t pre[257];
        uint8_t rnd[32] = {0};
        pre[0] = 0;
        pre[1] = (uint8_t)ctxlen;
        memcpy(pre + 2, ctx, ctxlen);
        r = pqcrystals_dilithium2_ref_signature_internal(
                sig, &siglen, m, mlen, pre, 2 + ctxlen, rnd, sk);
    } else {
        r = pqcrystals_dilithium2_ref_signature(sig, &siglen, m, mlen,
                                                ctxlen ? ctx : NULL,
                                                ctxlen, sk);
    }
    if (r) { fprintf(stderr, "sign failed\n"); return 2; }
    if (write_file(sig_out, sig, siglen)) return 2;
    printf("sign: sig %zu B over msg %zu B, ctx %zu B%s\n",
           siglen, mlen, ctxlen, deterministic ? " (deterministic)" : "");
    return 0;
}

static int do_verify(const char *pk_in, const char *msg_in,
                     const char *sig_in, const char *ctxfile) {
    size_t pklen, mlen, siglen;
    uint8_t *pk = read_file(pk_in, &pklen);
    uint8_t *m = read_file(msg_in, &mlen);
    uint8_t *sig = read_file(sig_in, &siglen);
    if (!pk || !m || !sig) return 2;
    if (pklen != pqcrystals_dilithium2_PUBLICKEYBYTES) {
        fprintf(stderr, "bad pk length %zu\n", pklen); return 2;
    }
    uint8_t ctx[256];
    size_t ctxlen = 0;
    if (read_ctx(ctxfile, ctx, &ctxlen)) return 2;
    int r = pqcrystals_dilithium2_ref_verify(sig, siglen, m, mlen,
                                             ctxlen ? ctx : NULL,
                                             ctxlen, pk);
    printf("%s\n", r == 0 ? "VALID" : "INVALID");
    return r == 0 ? 0 : 1;
}

static int do_sign_internal(const char *sk_in, const char *pre_in,
                            const char *msg_in, const char *sig_out,
                            const char *rndfile) {
    size_t sklen, prelen, mlen;
    uint8_t *sk = read_file(sk_in, &sklen);
    uint8_t *pre = read_file(pre_in, &prelen);
    uint8_t *m = read_file(msg_in, &mlen);
    if (!sk || !pre || !m) return 2;
    if (sklen != pqcrystals_dilithium2_SECRETKEYBYTES) {
        fprintf(stderr, "bad sk length %zu\n", sklen); return 2;
    }
    uint8_t rnd[32];
    if (rndfile && !strcmp(rndfile, "zeros")) {
        memset(rnd, 0, sizeof rnd);
    } else if (rndfile) {
        size_t rn;
        uint8_t *rb = read_file(rndfile, &rn);
        if (!rb || rn != 32) {
            fprintf(stderr, "bad rnd file\n"); return 2;
        }
        memcpy(rnd, rb, 32);
        free(rb);
    } else {
        randombytes(rnd, sizeof rnd);
    }
    uint8_t sig[pqcrystals_dilithium2_BYTES];
    size_t siglen = 0;
    int r = pqcrystals_dilithium2_ref_signature_internal(
            sig, &siglen, m, mlen, pre, prelen, rnd, sk);
    if (r) { fprintf(stderr, "sign_internal failed\n"); return 2; }
    if (write_file(sig_out, sig, siglen)) return 2;
    printf("sign_internal: sig %zu B, pre %zu B, msg %zu B\n",
           siglen, prelen, mlen);
    return 0;
}

static int do_verify_internal(const char *pk_in, const char *pre_in,
                              const char *msg_in, const char *sig_in) {
    size_t pklen, prelen, mlen, siglen;
    uint8_t *pk = read_file(pk_in, &pklen);
    uint8_t *pre = read_file(pre_in, &prelen);
    uint8_t *m = read_file(msg_in, &mlen);
    uint8_t *sig = read_file(sig_in, &siglen);
    if (!pk || !pre || !m || !sig) return 2;
    if (pklen != pqcrystals_dilithium2_PUBLICKEYBYTES) {
        fprintf(stderr, "bad pk length %zu\n", pklen); return 2;
    }
    int r = pqcrystals_dilithium2_ref_verify_internal(sig, siglen, m, mlen,
                                                      pre, prelen, pk);
    printf("%s\n", r == 0 ? "VALID" : "INVALID");
    return r == 0 ? 0 : 1;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s keypair|sign|sign_det|verify|"
                "sign_internal|verify_internal ...\n", argv[0]);
        return 2;
    }
    if (!strcmp(argv[1], "keypair") && argc == 4)
        return do_keypair(argv[2], argv[3]);
    if (!strcmp(argv[1], "sign") && (argc == 5 || argc == 6))
        return do_sign(argv[2], argv[3], argv[4],
                       argc == 6 ? argv[5] : NULL, 0);
    if (!strcmp(argv[1], "sign_det") && (argc == 5 || argc == 6))
        return do_sign(argv[2], argv[3], argv[4],
                       argc == 6 ? argv[5] : NULL, 1);
    if (!strcmp(argv[1], "verify") && (argc == 5 || argc == 6))
        return do_verify(argv[2], argv[3], argv[4],
                         argc == 6 ? argv[5] : NULL);
    if (!strcmp(argv[1], "sign_internal") &&
        (argc == 6 || argc == 7))
        return do_sign_internal(argv[2], argv[3], argv[4], argv[5],
                                argc == 7 ? argv[6] : NULL);
    if (!strcmp(argv[1], "verify_internal") && argc == 6)
        return do_verify_internal(argv[2], argv[3], argv[4], argv[5]);
    fprintf(stderr, "bad usage\n");
    return 2;
}
