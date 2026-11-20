#ifndef DENC_RAND_H
#define DENC_RAND_H

#include <stddef.h>
#include <stdint.h>

/* Cryptographically secure random bytes from the OS (getentropy / arc4random
 * / /dev/urandom fallback). Returns DENC_OK or DENC_ERR_CRYPTO. */
int denc_random(uint8_t *buf, size_t len);

#endif
