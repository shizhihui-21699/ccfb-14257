#include "chacha20.h"
#include "common.h"

#define ROTL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define QR(a, b, c, d) do {            \
    a += b; d ^= a; d = ROTL32(d, 16); \
    c += d; b ^= c; b = ROTL32(b, 12); \
    a += b; d ^= a; d = ROTL32(d, 8);  \
    c += d; b ^= c; b = ROTL32(b, 7);  \
} while (0)

static void chacha20_block(uint32_t st[16], uint8_t out[64]) {
    uint32_t x[16];
    memcpy(x, st, sizeof(x));
    for (int i = 0; i < 10; i++) {
        /* column rounds */
        QR(x[0], x[4], x[ 8], x[12]);
        QR(x[1], x[5], x[ 9], x[13]);
        QR(x[2], x[6], x[10], x[14]);
        QR(x[3], x[7], x[11], x[15]);
        /* diagonal rounds (RFC 8439 section 2.3) */
        QR(x[0], x[5], x[10], x[15]);
        QR(x[1], x[6], x[11], x[12]);
        QR(x[2], x[7], x[ 8], x[13]);
        QR(x[3], x[4], x[ 9], x[14]);
    }
    for (int i = 0; i < 16; i++) {
        uint32_t v = x[i] + st[i];
        out[i * 4 + 0] = (uint8_t)v;
        out[i * 4 + 1] = (uint8_t)(v >> 8);
        out[i * 4 + 2] = (uint8_t)(v >> 16);
        out[i * 4 + 3] = (uint8_t)(v >> 24);
    }
}

void chacha20_init(chacha20_ctx *ctx, const uint8_t key[CHACHA20_KEY_SIZE],
                   const uint8_t nonce[CHACHA20_NONCE_SIZE]) {
    static const uint8_t sigma[16] = {
        'e','x','p','a','n','d',' ','3','2','-','b','y','t','e',' ','k'
    };
    for (int i = 0; i < 4; i++)
        ctx->state[i] = rd32(sigma + i * 4);
    for (int i = 0; i < 8; i++)
        ctx->state[4 + i] = rd32(key + i * 4);
    ctx->state[12] = 0; /* block counter */
    ctx->state[13] = rd32(nonce + 0);
    ctx->state[14] = rd32(nonce + 4);
    ctx->state[15] = rd32(nonce + 8);
    ctx->counter = 0;
    ctx->ks_used = 64; /* force a fresh block on first crypt call */
}

void chacha20_crypt(chacha20_ctx *ctx, const uint8_t *in, uint8_t *out,
                    size_t len) {
    while (len > 0) {
        if (ctx->ks_used == 64) {
            ctx->state[12] = ctx->counter;
            chacha20_block(ctx->state, ctx->keystream);
            ctx->counter++;
            ctx->ks_used = 0;
        }
        size_t take = 64 - ctx->ks_used;
        if (take > len) take = len;
        for (size_t i = 0; i < take; i++)
            out[i] = in[i] ^ ctx->keystream[ctx->ks_used + i];
        ctx->ks_used += take;
        in += take; out += take; len -= take;
    }
}

void chacha20_sector(const uint8_t key[CHACHA20_KEY_SIZE], uint64_t sector,
                     uint32_t domain, const uint8_t *in, uint8_t *out,
                     size_t len) {
    uint8_t nonce[CHACHA20_NONCE_SIZE];
    wr64(nonce, sector);
    wr32(nonce + 8, domain);
    chacha20_ctx ctx;
    chacha20_init(&ctx, key, nonce);
    chacha20_crypt(&ctx, in, out, len);
    denc_explicit_bzero(&ctx, sizeof(ctx));
}
