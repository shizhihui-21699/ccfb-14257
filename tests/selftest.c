/* Known-answer tests against published vectors:
 *   SHA-256: FIPS 180-4 examples
 *   HMAC-SHA256: RFC 4231 test case 1
 *   ChaCha20: RFC 8439 section 2.4.2 test vector
 *   PBKDF2-HMAC-SHA256: RFC 7914 test vector
 */
#include "chacha20.h"
#include "sha256.h"
#include "kdf.h"
#include "common.h"
#include <stdio.h>

static int eq(const uint8_t *a, const uint8_t *b, size_t n) {
    return memcmp(a, b, n) == 0;
}

static void hex(const uint8_t *p, size_t n) {
    for (size_t i = 0; i < n; i++) printf("%02x", p[i]);
}

static int test_sha256(void) {
    uint8_t d[32];
    sha256((const uint8_t *)"abc", 3, d);
    const uint8_t want_abc[32] = {
        0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,
        0x22,0x23,0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,
        0xf2,0x00,0x15,0xad};
    if (!eq(d, want_abc, 32)) { printf("SHA256(abc) FAIL\n"); return 1; }

    sha256((const uint8_t *)"", 0, d);
    const uint8_t want_empty[32] = {
        0xe3,0xb0,0xc4,0x42,0x98,0xfc,0x1c,0x14,0x9a,0xfb,0xf4,0xc8,0x99,0x6f,
        0xb9,0x24,0x27,0xae,0x41,0xe4,0x64,0x9b,0x93,0x4c,0xa4,0x95,0x99,0x1b,
        0x78,0x52,0xb8,0x55};
    if (!eq(d, want_empty, 32)) { printf("SHA256(empty) FAIL\n"); return 1; }
    printf("PASS sha256 (FIPS 180-4)\n");
    return 0;
}

static int test_hmac(void) {
    /* RFC 4231 case 1: key=0x0b x20, data="Hi There" */
    uint8_t key[20]; memset(key, 0x0b, 20);
    uint8_t mac[32];
    hmac_sha256(key, 20, (const uint8_t *)"Hi There", 8, mac);
    const uint8_t want[32] = {
        0xb0,0x34,0x4c,0x61,0xd8,0xdb,0x38,0x53,0x5c,0xa8,0xaf,0xce,0xaf,0x0b,
        0xf1,0x2b,0x88,0x1d,0xc2,0x00,0xc9,0x83,0x3d,0xa7,0x26,0xe9,0x37,0x6c,
        0x2e,0x32,0xcf,0xf7};
    if (!eq(mac, want, 32)) { printf("HMAC FAIL: "); hex(mac,32); printf("\n");
                               return 1; }
    printf("PASS hmac-sha256 (RFC 4231)\n");
    return 0;
}

static int test_chacha20(void) {
    /* RFC 8439 2.4.2 */
    uint8_t key[32]; for (int i=0;i<32;i++) key[i]=(uint8_t)i;
    /* RFC 8439 2.4.2: state last row = [counter=1 | nonce(3 words)].
     * nonce bytes are 00:00:00:00 00:00:00:4a 00:00:00:00 */
    uint8_t nonce[12] = {0,0,0,0, 0,0,0,0x4a, 0,0,0,0};
    const char *plain =
        "Ladies and Gentlemen of the class of '99: If I could offer you "
        "only one tip for the future, sunscreen would be it.";
    size_t plen = 114;
    uint8_t in[256], out[256], back[256];
    memcpy(in, plain, plen);
    chacha20_ctx ctx;
    chacha20_init(&ctx, key, nonce);
    ctx.counter = 1;                 /* RFC vector starts at block counter 1 */
    chacha20_crypt(&ctx, in, out, plen);
    const uint8_t want_prefix[32] = {
        0x6e,0x2e,0x35,0x9a,0x25,0x68,0xf9,0x80,0x41,0xba,0x07,0x28,0xdd,0x0d,
        0x69,0x81,0xe9,0x7e,0x7a,0xec,0x1d,0x43,0x60,0xc2,0x0a,0x27,0xaf,0xcc,
        0xfd,0x9f,0xae,0x0b};
    if (!eq(out, want_prefix, 32)) { printf("ChaCha20 FAIL\n"); return 1; }
    chacha20_init(&ctx, key, nonce);
    ctx.counter = 1;
    chacha20_crypt(&ctx, out, back, plen);
    if (!eq(back, in, plen)) { printf("ChaCha20 not invertible\n"); return 1; }
    printf("PASS chacha20 (RFC 8439)\n");
    return 0;
}

static int test_pbkdf2(void) {
    /* RFC 7914 section 11, case 1: P="passwd", S="salt", c=1, dkLen=64 */
    const uint8_t *P = (const uint8_t *)"passwd";
    const uint8_t *S = (const uint8_t *)"salt";
    uint8_t dk[64];
    int rc = pbkdf2_hmac_sha256(P, 6, S, 4, 1, dk, 64);
    if (rc) { printf("PBKDF2 error\n"); return 1; }
    const uint8_t want[32] = {
        0x55,0xac,0x04,0x6e,0x56,0xe3,0x08,0x9f,0xec,0x16,0x91,0xc2,0x25,0x44,
        0xb6,0x05,0xf9,0x41,0x85,0x21,0x6d,0xde,0x04,0x65,0xe6,0x8b,0x9d,0x57,
        0xc2,0x0d,0xac,0xbc};
    if (!eq(dk, want, 32)) { printf("PBKDF2 FAIL: "); hex(dk,32);
                              printf("\n"); return 1; }
    printf("PASS pbkdf2-hmac-sha256 (RFC 7914)\n");
    return 0;
}

int main(void) {
    int fails = 0;
    fails += test_sha256();
    fails += test_hmac();
    fails += test_chacha20();
    fails += test_pbkdf2();
    if (fails) { printf("SELFTEST FAILED\n"); return 1; }
    printf("all crypto known-answer tests passed\n");
    return 0;
}
