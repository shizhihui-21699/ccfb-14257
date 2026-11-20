#include "kdf.h"
#include "sha256.h"
#include "common.h"

int pbkdf2_hmac_sha256(const uint8_t *password, size_t pwlen,
                       const uint8_t *salt, size_t salt_len,
                       uint32_t iterations, uint8_t *out, size_t outlen) {
    if (iterations == 0) return DENC_ERR_CRYPTO;

    uint8_t u[SHA256_DIGEST_SIZE], t[SHA256_DIGEST_SIZE];
    uint32_t block = 1;
    size_t off = 0;

    while (off < outlen) {
        uint8_t msg[PBKDF2_SALT_SIZE + 4];
        memcpy(msg, salt, salt_len);
        /* INT_32_BE(block) per RFC 8018 section 5.2 */
        uint32_t be = block;
        msg[salt_len + 0] = (uint8_t)(be >> 24);
        msg[salt_len + 1] = (uint8_t)(be >> 16);
        msg[salt_len + 2] = (uint8_t)(be >> 8);
        msg[salt_len + 3] = (uint8_t)be;
        hmac_sha256(password, pwlen, msg, salt_len + 4, u);
        memcpy(t, u, SHA256_DIGEST_SIZE);

        for (uint32_t i = 1; i < iterations; i++) {
            hmac_sha256(password, pwlen, u, SHA256_DIGEST_SIZE, u);
            for (int j = 0; j < SHA256_DIGEST_SIZE; j++) t[j] ^= u[j];
        }
        size_t take = outlen - off;
        if (take > SHA256_DIGEST_SIZE) take = SHA256_DIGEST_SIZE;
        memcpy(out + off, t, take);
        off += take;
        block++;
    }
    denc_explicit_bzero(u, sizeof(u));
    denc_explicit_bzero(t, sizeof(t));
    return DENC_OK;
}
