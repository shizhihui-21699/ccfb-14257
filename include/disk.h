#ifndef DENC_DISK_H
#define DENC_DISK_H

#include <stdio.h>
#include <stdint.h>
#include "kdf.h"

#define DENC_SECTOR_SIZE   4096
#define DENC_HEADER_SLOTS  2            /* outer at 0, hidden at 1 */
/* Header reservation expressed in SECTORS (each slot is one sector). */
#define DENC_HEADER_RESERVED DENC_HEADER_SLOTS

#define DENC_MAGIC         0x44454e43u  /* "DENC" */
#define DENC_VERSION       1u
#define DENC_PBKDF2_ITER   200000u
#define DENC_NAME_MAX      127
#define DENC_MAX_EXTENTS   8

/* Domain tags for sector encryption nonces (nonce = sector index || domain).
 * Keeping separate domains means identical plaintext at the same sector in
 * the two volumes never produces identical ciphertext. */
#define DOMAIN_OUTER 1u
#define DOMAIN_HIDDEN 2u
#define DOMAIN_HEADER 3u

/* Plaintext payload of an encrypted header slot. The whole sector is
 * encrypted; fields outside this struct are random padding, so an attacker
 * cannot even tell whether a slot contains a structured header. */
typedef struct {
    uint32_t magic;
    uint32_t version;
    uint32_t pbkdf2_iter;
    uint32_t domain;                 /* DOMAIN_OUTER / DOMAIN_HIDDEN */
    uint8_t  key[32];                /* volume data key, wrapped by KEK */
    uint64_t vol_sectors;            /* size of this volume's data region */
    uint64_t hidden_start;           /* outer only: protected tail boundary */
    uint64_t create_time;            /* decoy metadata; never updated */
    uint8_t  hmac[32];               /* header integrity, keyed by KEK */
} denc_header_t;

typedef struct {
    FILE     *fp;
    char     *path;
    uint8_t   kek[32];               /* derived from password */
    uint8_t   key[32];               /* unwrapped volume data key */
    uint32_t  domain;
    uint64_t  total_sectors;         /* file size / 4096 */
    uint64_t  vol_sectors;           /* sectors available to the volume */
    uint64_t  base_sector;           /* absolute start of this volume's data
                                        region: 0 for outer; the outer tail
                                        offset for the hidden volume */
    uint64_t  hidden_start;          /* 0 unless outer with hidden volume */
    int       keep_mtime;
    int64_t   saved_mtime_ns[2];     /* st_atim, st_mtim to restore */
} denc_disk_t;

/* Create a brand-new container: fixed size, every byte random, two header
 * slots written (hidden slot receives an independently random fake header). */
int disk_create(const char *path, uint64_t total_sectors,
                const uint8_t *pw, size_t pwlen, uint64_t hidden_sectors,
                int keep_mtime);

/* Open with a password. Tries slot 0 then slot 1. On success *out is filled. */
int disk_open(denc_disk_t *d, const char *path,
              const uint8_t *pw, size_t pwlen, int keep_mtime);
/* Open a specific header slot (0 = outer, 1 = hidden). Fails with
 * DENC_ERR_FORMAT if that slot does not validate under the password. */
int disk_open_slot(denc_disk_t *d, const char *path, int slot,
                   const uint8_t *pw, size_t pwlen, int keep_mtime);
void disk_close(denc_disk_t *d);

/* Encrypted sector I/O over a volume's data region. sector is a volume-
 * relative index; the header reservation is added internally. */
int disk_read_sector(denc_disk_t *d, uint64_t sector, uint8_t *buf);
int disk_write_sector(denc_disk_t *d, uint64_t sector, const uint8_t *buf);

/* Raw slot I/O (used by create/chpass and by the forensic analyzer). */
int disk_read_slot_raw(const char *path, int slot, uint8_t buf[DENC_SECTOR_SIZE]);
int disk_write_slot_raw(const char *path, int slot,
                        const uint8_t buf[DENC_SECTOR_SIZE]);

/* Encrypt/decrypt a header slot under a password. */
int header_seal(const uint8_t *pw, size_t pwlen, const denc_header_t *h,
                uint8_t out[DENC_SECTOR_SIZE]);
int header_open(const uint8_t *pw, size_t pwlen,
                const uint8_t in[DENC_SECTOR_SIZE], denc_header_t *h);

/* Fill n_sectors of random data starting at absolute sector abs_start. */
int disk_scrub_range(FILE *fp, uint64_t abs_start, uint64_t n_sectors);

int disk_flush(denc_disk_t *d);
void disk_restore_mtime(denc_disk_t *d);

#endif
