#ifndef DENC_VOL_H
#define DENC_VOL_H

#include "fs.h"

typedef struct {
    denc_disk_t disk;
    denc_fs_t   fs;
    int         is_hidden;
    int         keep_mtime;
} denc_session_t;

/* Create container. hidden_sectors == 0 means outer-only (slot 1 stays
 * random). */
int vol_create(const char *path, uint64_t total_sectors,
               const uint8_t *pw, size_t pwlen, uint64_t hidden_sectors,
               int keep_mtime);

/* Open with a password. If the outer volume advertises a hidden tail, the
 * session mounts protected: that tail becomes a forbidden window the FS
 * allocator will never touch. Opening the hidden volume mounts it directly.
 */
int vol_open(denc_session_t *s, const char *path,
             const uint8_t *pw, size_t pwlen, int keep_mtime);
/* Force the hidden slot (1). Fails if no hidden volume validates. */
int vol_open_hidden(denc_session_t *s, const char *path,
                    const uint8_t *pw, size_t pwlen, int keep_mtime);
int vol_close(denc_session_t *s);

/* Rewrap both accessible headers under a new password (outer + hidden if
 * the password opens the hidden slot; otherwise outer only). */
int vol_chpass(const char *path, const uint8_t *oldpw, size_t oldlen,
               const uint8_t *newpw, size_t newlen);

/* Randomize free outer blocks (deniability churn against snapshot diffing). */
int vol_churn(denc_session_t *s, uint64_t max_blocks, uint64_t *scrubbed);

#endif
