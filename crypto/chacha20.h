#ifndef DENC_CHACHA20_H
#define DENC_CHACHA20_H

#include <stddef.h>
#include <stdint.h>

#define CHACHA20_KEY_SIZE 32
#define CHACHA20_NONCE_SIZE 12

typedef struct {
    uint32_t state[16];
    uint32_t counter;       /* block counter, kept between calls */
    uint8_t  keystream[64]; /* buffered keystream for tail bytes */
    size_t   ks_used;       /* bytes consumed from keystream */
} chacha20_ctx;

/* key = 32 bytes, nonce = 12 bytes (IETF variant, 32-bit block counter). */
void chacha20_init(chacha20_ctx *ctx, const uint8_t key[CHACHA20_KEY_SIZE],
                   const uint8_t nonce[CHACHA20_NONCE_SIZE]);
void chacha20_crypt(chacha20_ctx *ctx, const uint8_t *in, uint8_t *out,
                    size_t len);

/* One-shot helper for a single sector: nonce = 64-bit sector index ||
 * 32-bit domain tag, counter resets to zero inside the sector. */
void chacha20_sector(const uint8_t key[CHACHA20_KEY_SIZE], uint64_t sector,
                     uint32_t domain, const uint8_t *in, uint8_t *out,
                     size_t len);

#endif
