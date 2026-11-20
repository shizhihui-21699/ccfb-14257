#ifndef DENC_COMMON_H
#define DENC_COMMON_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* On-disk structures are little-endian; helpers convert explicitly. */

static inline uint16_t rd16(const uint8_t *p) {
    return (uint16_t)(p[0] | ((uint16_t)p[1] << 8));
}
static inline uint32_t rd32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static inline uint64_t rd64(const uint8_t *p) {
    return (uint64_t)rd32(p) | ((uint64_t)rd32(p + 4) << 32);
}
static inline void wr16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
}
static inline void wr32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}
static inline void wr64(uint8_t *p, uint64_t v) {
    wr32(p, (uint32_t)v); wr32(p + 4, (uint32_t)(v >> 32));
}

void denc_explicit_bzero(void *p, size_t n);

#define DENC_OK            0
#define DENC_ERR_USAGE    (-1)
#define DENC_ERR_IO       (-2)
#define DENC_ERR_CRYPTO   (-3)
#define DENC_ERR_FORMAT   (-4)   /* bad password / corrupt structure */
#define DENC_ERR_NOSPACE  (-5)
#define DENC_ERR_NOENT    (-6)
#define DENC_ERR_EXISTS   (-7)
#define DENC_ERR_DENIED   (-8)   /* write blocked to protect hidden region */

const char *denc_strerror(int rc);

/* Deterministic PRNG seeded by CSPRNG, used only to pad unused space with
 * key-derived randomness when a key is available (see disk.c). */
#endif
