#include "disk.h"
#include "chacha20.h"
#include "sha256.h"
#include "kdf.h"
#include "rand.h"
#include "common.h"

#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>

#define SALT_OFF   0
#define ITER_OFF   32
#define CT_OFF     36
#define CT_LEN     (DENC_SECTOR_SIZE - CT_OFF)   /* 4060 bytes */

int header_seal(const uint8_t *pw, size_t pwlen, const denc_header_t *hin,
                uint8_t out[DENC_SECTOR_SIZE]) {
    int rc = DENC_OK;
    denc_header_t h = *hin;
    h.pbkdf2_iter = hin->pbkdf2_iter ? hin->pbkdf2_iter : DENC_PBKDF2_ITER;

    uint8_t *plain = calloc(1, CT_LEN);
    if (!plain) return DENC_ERR_IO;
    /* Random padding around the fixed struct so the ciphertext layout
     * reveals nothing about which fields are meaningful. */
    if (denc_random(plain, CT_LEN) != DENC_OK ||
        denc_random(out + SALT_OFF, PBKDF2_SALT_SIZE) != DENC_OK) {
        rc = DENC_ERR_CRYPTO; goto out;
    }
    wr32(out + ITER_OFF, h.pbkdf2_iter);

    uint8_t kek[32];
    if (pbkdf2_hmac_sha256(pw, pwlen, out + SALT_OFF, PBKDF2_SALT_SIZE,
                           h.pbkdf2_iter, kek, sizeof(kek)) != DENC_OK) {
        rc = DENC_ERR_CRYPTO; goto out_kek;
    }
    /* Integrity tag inside the encrypted blob: a wrong password yields
     * random plaintext and fails here, with no oracle on the wire. */
    hmac_sha256(kek, sizeof(kek), (const uint8_t *)&h,
                offsetof(denc_header_t, hmac), h.hmac);
    memcpy(plain, &h, sizeof(h));

    /* Fixed nonce for header slots: the DOMAIN_HEADER tag and the unique
     * per-slot salt already separate contexts; seal/open must agree. */
    chacha20_sector(kek, 0, DOMAIN_HEADER,
                    plain, out + CT_OFF, CT_LEN);
    denc_explicit_bzero(kek, sizeof(kek));
    denc_explicit_bzero(&h, sizeof(h));
out_kek:
    denc_explicit_bzero(plain, CT_LEN);
out:
    free(plain);
    return rc;
}

int header_open(const uint8_t *pw, size_t pwlen,
                const uint8_t in[DENC_SECTOR_SIZE], denc_header_t *h) {
    uint32_t iter = rd32(in + ITER_OFF);
    if (iter == 0 || iter > 10u * 1000u * 1000u) return DENC_ERR_FORMAT;

    uint8_t kek[32], *plain = calloc(1, CT_LEN);
    if (!plain) return DENC_ERR_IO;

    if (pbkdf2_hmac_sha256(pw, pwlen, in + SALT_OFF, PBKDF2_SALT_SIZE,
                           iter, kek, sizeof(kek)) != DENC_OK) {
        free(plain);
        return DENC_ERR_CRYPTO;
    }
    chacha20_sector(kek, 0, DOMAIN_HEADER, in + CT_OFF, plain, CT_LEN);
    memcpy(h, plain, sizeof(*h));

    int ok = (h->magic == DENC_MAGIC && h->version == DENC_VERSION &&
              (h->domain == DOMAIN_OUTER || h->domain == DOMAIN_HIDDEN) &&
              h->vol_sectors > 0);
    if (ok) {
        uint8_t mac[32];
        hmac_sha256(kek, sizeof(kek), plain,
                    offsetof(denc_header_t, hmac), mac);
        ok = (memcmp(mac, h->hmac, 32) == 0);
        denc_explicit_bzero(mac, sizeof(mac));
    }
    denc_explicit_bzero(kek, sizeof(kek));
    denc_explicit_bzero(plain, CT_LEN);
    free(plain);
    return ok ? DENC_OK : DENC_ERR_FORMAT;
}

static void fill_header(denc_header_t *h, uint32_t domain, const uint8_t key[32],
                        uint64_t vol_sectors, uint64_t hidden_start) {
    memset(h, 0, sizeof(*h));
    h->magic = DENC_MAGIC;
    h->version = DENC_VERSION;
    h->pbkdf2_iter = DENC_PBKDF2_ITER;
    h->domain = domain;
    memcpy(h->key, key, 32);
    h->vol_sectors = vol_sectors;
    h->hidden_start = hidden_start;
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    h->create_time = (uint64_t)ts.tv_sec;
}

int disk_scrub_range(FILE *fp, uint64_t abs_start, uint64_t n_sectors) {
    uint8_t buf[16 * DENC_SECTOR_SIZE];
    uint64_t done = 0;
    if (fseeko(fp, (off_t)abs_start * DENC_SECTOR_SIZE, SEEK_SET) != 0)
        return DENC_ERR_IO;
    while (done < n_sectors) {
        uint64_t chunk = n_sectors - done;
        if (chunk > 16) chunk = 16;
        if (denc_random(buf, (size_t)chunk * DENC_SECTOR_SIZE) != DENC_OK)
            return DENC_ERR_CRYPTO;
        if (fwrite(buf, DENC_SECTOR_SIZE, (size_t)chunk, fp) != (size_t)chunk)
            return DENC_ERR_IO;
        done += chunk;
    }
    return DENC_OK;
}

static int full_fsync(FILE *fp) {
    if (fflush(fp) != 0) return DENC_ERR_IO;
    int fd = fileno(fp);
#if defined(__APPLE__)
    if (fcntl(fd, F_FULLFSYNC) != 0) return DENC_ERR_IO;
#else
    if (fsync(fd) != 0) return DENC_ERR_IO;
#endif
    return DENC_OK;
}

int disk_flush(denc_disk_t *d) { return full_fsync(d->fp); }

int disk_create(const char *path, uint64_t total_sectors,
                const uint8_t *pw, size_t pwlen, uint64_t hidden_sectors,
                int keep_mtime) {
    if (total_sectors <= DENC_HEADER_RESERVED + 4) return DENC_ERR_USAGE;
    int rc = DENC_OK;
    FILE *fp = fopen(path, "w+b");
    if (!fp) return DENC_ERR_IO;

    uint64_t vol_sectors = total_sectors - DENC_HEADER_RESERVED;
    if (hidden_sectors >= vol_sectors) { rc = DENC_ERR_USAGE; goto out; }

    /* 1. Whole container is random. Sparse files would show holes under
     * stat(1)/fiemap, so we write every byte. */
    rc = disk_scrub_range(fp, 0, total_sectors);
    if (rc != DENC_OK) goto out;

    uint8_t okey[32], hkey[32];
    if (denc_random(okey, 32) != DENC_OK ||
        (hidden_sectors && denc_random(hkey, 32) != DENC_OK)) {
        rc = DENC_ERR_CRYPTO; goto out;
    }

    /* 2. Outer header in slot 0. */
    denc_header_t oh;
    uint64_t hstart = hidden_sectors ? vol_sectors - hidden_sectors : 0;
    fill_header(&oh, DOMAIN_OUTER, okey, vol_sectors, hstart);
    uint8_t slot[DENC_SECTOR_SIZE];
    rc = header_seal(pw, pwlen, &oh, slot);
    if (rc != DENC_OK) goto out;
    if (fseeko(fp, 0, SEEK_SET) != 0 ||
        fwrite(slot, 1, DENC_SECTOR_SIZE, fp) != DENC_SECTOR_SIZE) {
        rc = DENC_ERR_IO; goto out;
    }

    /* 3. Hidden header in slot 1. Without a hidden volume the slot simply
     * keeps the container-wide random fill: indistinguishable from the
     * ciphertext of a real slot to anyone without the password. */
    if (hidden_sectors) {
        denc_header_t hh;
        fill_header(&hh, DOMAIN_HIDDEN, hkey, hidden_sectors, 0);
        rc = header_seal(pw, pwlen, &hh, slot);
        if (rc != DENC_OK) goto out;
        if (fseeko(fp, DENC_SECTOR_SIZE, SEEK_SET) != 0 ||
            fwrite(slot, 1, DENC_SECTOR_SIZE, fp) != DENC_SECTOR_SIZE) {
            rc = DENC_ERR_IO; goto out;
        }
        denc_explicit_bzero(hkey, sizeof(hkey));
    }
    denc_explicit_bzero(okey, sizeof(okey));
    denc_explicit_bzero(slot, sizeof(slot));
    rc = full_fsync(fp);
out:
    if (fp) fclose(fp);
    if (rc != DENC_OK) remove(path);
    (void)keep_mtime;
    return rc;
}

int disk_read_slot_raw(const char *path, int slot,
                       uint8_t buf[DENC_SECTOR_SIZE]) {
    FILE *fp = fopen(path, "rb");
    if (!fp) return DENC_ERR_IO;
    int rc = DENC_OK;
    if (fseeko(fp, (off_t)slot * DENC_SECTOR_SIZE, SEEK_SET) != 0 ||
        fread(buf, 1, DENC_SECTOR_SIZE, fp) != DENC_SECTOR_SIZE)
        rc = DENC_ERR_IO;
    fclose(fp);
    return rc;
}

int disk_write_slot_raw(const char *path, int slot,
                        const uint8_t buf[DENC_SECTOR_SIZE]) {
    FILE *fp = fopen(path, "r+b");
    if (!fp) return DENC_ERR_IO;
    int rc = DENC_OK;
    if (fseeko(fp, (off_t)slot * DENC_SECTOR_SIZE, SEEK_SET) != 0 ||
        fwrite(buf, 1, DENC_SECTOR_SIZE, fp) != DENC_SECTOR_SIZE)
        rc = DENC_ERR_IO;
    if (rc == DENC_OK) rc = full_fsync(fp);
    fclose(fp);
    return rc;
}

void disk_restore_mtime(denc_disk_t *d) {
    if (!d->keep_mtime) return;
#if defined(__APPLE__) || (defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L)
    struct timespec ts[2] = {
        { d->saved_mtime_ns[0] / 1000000000, d->saved_mtime_ns[0] % 1000000000 },
        { d->saved_mtime_ns[1] / 1000000000, d->saved_mtime_ns[1] % 1000000000 }
    };
    futimens(fileno(d->fp), ts);
#endif
}

int disk_open_slot(denc_disk_t *d, const char *path, int want_slot,
                   const uint8_t *pw, size_t pwlen, int keep_mtime) {
    memset(d, 0, sizeof(*d));
    struct stat st;
    d->fp = fopen(path, "r+b");
    if (!d->fp) return DENC_ERR_IO;
    d->path = strdup(path);
    if (fstat(fileno(d->fp), &st) != 0 ||
        st.st_size < (off_t)(DENC_HEADER_RESERVED * DENC_SECTOR_SIZE) ||
        (st.st_size % DENC_SECTOR_SIZE) != 0) {
        fclose(d->fp); free(d->path); return DENC_ERR_FORMAT;
    }
    d->total_sectors = (uint64_t)st.st_size / DENC_SECTOR_SIZE;
    d->keep_mtime = keep_mtime;
#if defined(__APPLE__)
    d->saved_mtime_ns[0] = st.st_atimespec.tv_sec * 1000000000LL
                         + st.st_atimespec.tv_nsec;
    d->saved_mtime_ns[1] = st.st_mtimespec.tv_sec * 1000000000LL
                         + st.st_mtimespec.tv_nsec;
#else
    d->saved_mtime_ns[0] = st.st_atim.tv_sec * 1000000000LL + st.st_atim.tv_nsec;
    d->saved_mtime_ns[1] = st.st_mtim.tv_sec * 1000000000LL + st.st_mtim.tv_nsec;
#endif

    uint8_t slot[DENC_SECTOR_SIZE];
    denc_header_t h;
    if (disk_read_slot_raw(path, want_slot, slot) != DENC_OK ||
        header_open(pw, pwlen, slot, &h) != DENC_OK) {
        denc_explicit_bzero(slot, sizeof(slot));
        fclose(d->fp); free(d->path); d->fp = NULL;
        return DENC_ERR_FORMAT;
    }
    denc_explicit_bzero(slot, sizeof(slot));
    memcpy(d->key, h.key, 32);
    d->domain = h.domain;
    d->vol_sectors = h.vol_sectors;
    d->hidden_start = h.hidden_start;
    if (h.domain == DOMAIN_HIDDEN) {
        /* Hidden data region begins at the outer volume's tail. The outer
         * data region spans (total - header reservation) sectors; the
         * hidden header stores its own length, so its base is the
         * difference. */
        uint64_t outer_vol = d->total_sectors - DENC_HEADER_RESERVED;
        d->base_sector = outer_vol - h.vol_sectors;
    } else {
        d->base_sector = 0;
    }
    denc_explicit_bzero(&h, sizeof(h));
    return DENC_OK;
}

int disk_open(denc_disk_t *d, const char *path,
              const uint8_t *pw, size_t pwlen, int keep_mtime) {
    /* Outer password first (slot 0); a password shared with the hidden
     * volume still opens the outer, protected mount by default. */
    int rc = disk_open_slot(d, path, 0, pw, pwlen, keep_mtime);
    if (rc == DENC_OK) return rc;
    return disk_open_slot(d, path, 1, pw, pwlen, keep_mtime);
}

void disk_close(denc_disk_t *d) {
    if (!d->fp) return;
    disk_restore_mtime(d);
    fclose(d->fp);
    denc_explicit_bzero(d->key, sizeof(d->key));
    denc_explicit_bzero(d->kek, sizeof(d->kek));
    free(d->path);
    d->fp = NULL;
}

int disk_read_sector(denc_disk_t *d, uint64_t sector, uint8_t *buf) {
    if (sector >= d->vol_sectors) return DENC_ERR_NOSPACE;
    uint64_t abs = DENC_HEADER_RESERVED + d->base_sector + sector;
    if (fseeko(d->fp, (off_t)abs * DENC_SECTOR_SIZE, SEEK_SET) != 0)
        return DENC_ERR_IO;
    if (fread(buf, 1, DENC_SECTOR_SIZE, d->fp) != DENC_SECTOR_SIZE)
        return DENC_ERR_IO;
    chacha20_sector(d->key, abs, d->domain, buf, buf, DENC_SECTOR_SIZE);
    return DENC_OK;
}

int disk_write_sector(denc_disk_t *d, uint64_t sector, const uint8_t *buf) {
    if (sector >= d->vol_sectors) return DENC_ERR_NOSPACE;
    uint64_t abs = DENC_HEADER_RESERVED + d->base_sector + sector;
    uint8_t tmp[DENC_SECTOR_SIZE];
    chacha20_sector(d->key, abs, d->domain, buf, tmp, DENC_SECTOR_SIZE);
    if (fseeko(d->fp, (off_t)abs * DENC_SECTOR_SIZE, SEEK_SET) != 0) {
        denc_explicit_bzero(tmp, sizeof(tmp));
        return DENC_ERR_IO;
    }
    size_t w = fwrite(tmp, 1, DENC_SECTOR_SIZE, d->fp);
    denc_explicit_bzero(tmp, sizeof(tmp));
    return w == DENC_SECTOR_SIZE ? DENC_OK : DENC_ERR_IO;
}
