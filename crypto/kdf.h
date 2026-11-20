#ifndef DENC_KDF_H
#define DENC_KDF_H

#include <stddef.h>
#include <stdint.h>

#define PBKDF2_SALT_SIZE 32

/* PBKDF2-HMAC-SHA256. salt_len is the actual salt length in bytes.
 * iterations is stored in the header so it can be raised without breaking
 * old containers. The block index is encoded big-endian per RFC 8018. */
int pbkdf2_hmac_sha256(const uint8_t *password, size_t pwlen,
                       const uint8_t *salt, size_t salt_len,
                       uint32_t iterations, uint8_t *out, size_t outlen);

#endif
