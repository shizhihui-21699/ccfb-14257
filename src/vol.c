#include "vol.h"
#include "rand.h"
#include "common.h"

int vol_create(const char *path, uint64_t total_sectors,
               const uint8_t *pw, size_t pwlen, uint64_t hidden_sectors,
               int keep_mtime) {
    int rc = disk_create(path, total_sectors, pw, pwlen, hidden_sectors,
                         keep_mtime);
    if (rc != DENC_OK) return rc;

    /* Outer file system over the whole data region; when a hidden volume
     * exists its tail is a forbidden window the outer allocator avoids. */
    denc_session_t s;
    memset(&s, 0, sizeof(s));
    rc = disk_open_slot(&s.disk, path, 0, pw, pwlen, keep_mtime);
    if (rc != DENC_OK) { remove(path); return rc; }

    uint64_t forbid_from = 0, forbid_to = 0;
    if (hidden_sectors) {
        forbid_to = s.disk.vol_sectors;
        forbid_from = forbid_to - hidden_sectors;
    }
    rc = fs_format(&s.fs, &s.disk, forbid_from, forbid_to);
    if (rc != DENC_OK) {
        fs_close(&s.fs); disk_close(&s.disk); remove(path); return rc;
    }
    disk_flush(&s.disk);
    fs_close(&s.fs);
    disk_close(&s.disk);

    /* Hidden file system: its data region is the outer volume's tail. */
    if (hidden_sectors) {
        denc_session_t hs;
        memset(&hs, 0, sizeof(hs));
        rc = disk_open_slot(&hs.disk, path, 1, pw, pwlen, keep_mtime);
        if (rc != DENC_OK) { remove(path); return rc; }
        if (hs.disk.domain != DOMAIN_HIDDEN) {
            disk_close(&hs.disk); remove(path); return DENC_ERR_FORMAT;
        }
        hs.is_hidden = 1;
        rc = fs_format(&hs.fs, &hs.disk, 0, 0);
        if (rc == DENC_OK) { disk_flush(&hs.disk); }
        fs_close(&hs.fs);
        disk_close(&hs.disk);
        if (rc != DENC_OK) { remove(path); return rc; }
    }
    return DENC_OK;
}

static int vol_open_at(denc_session_t *s, const char *path,
                       const uint8_t *pw, size_t pwlen, int keep_mtime,
                       int force_slot) {
    memset(s, 0, sizeof(*s));
    int rc;
    if (force_slot >= 0)
        rc = disk_open_slot(&s->disk, path, force_slot, pw, pwlen,
                            keep_mtime);
    else
        rc = disk_open(&s->disk, path, pw, pwlen, keep_mtime);
    if (rc != DENC_OK) return rc;
    s->keep_mtime = keep_mtime;
    s->is_hidden = (s->disk.domain == DOMAIN_HIDDEN);

    uint64_t ff = 0, ft = 0;
    if (!s->is_hidden && s->disk.hidden_start > 0) {
        /* Protected outer mount: hidden tail is untouchable. */
        ff = s->disk.hidden_start;
        ft = s->disk.vol_sectors;
    }
    rc = fs_open(&s->fs, &s->disk, ff, ft);
    if (rc != DENC_OK) disk_close(&s->disk);
    return rc;
}

int vol_open(denc_session_t *s, const char *path,
             const uint8_t *pw, size_t pwlen, int keep_mtime) {
    return vol_open_at(s, path, pw, pwlen, keep_mtime, -1);
}

int vol_open_hidden(denc_session_t *s, const char *path,
                    const uint8_t *pw, size_t pwlen, int keep_mtime) {
    return vol_open_at(s, path, pw, pwlen, keep_mtime, 1);
}

int vol_close(denc_session_t *s) {
    if (s->fs.disk) fs_close(&s->fs);
    if (s->disk.fp) disk_close(&s->disk);
    memset(s, 0, sizeof(*s));
    return DENC_OK;
}

int vol_chpass(const char *path, const uint8_t *oldpw, size_t oldlen,
               const uint8_t *newpw, size_t newlen) {
    uint8_t raw[DENC_SECTOR_SIZE], out[DENC_SECTOR_SIZE];
    denc_header_t h;
    int touched = 0, rc;
    for (int slot = 0; slot < DENC_HEADER_SLOTS; slot++) {
        rc = disk_read_slot_raw(path, slot, raw);
        if (rc != DENC_OK) return rc;
        if (header_open(oldpw, oldlen, raw, &h) != DENC_OK) continue;
        rc = header_seal(newpw, newlen, &h, out);
        if (rc != DENC_OK) return rc;
        rc = disk_write_slot_raw(path, slot, out);
        if (rc != DENC_OK) return rc;
        touched++;
        denc_explicit_bzero(&h, sizeof(h));
    }
    return touched ? DENC_OK : DENC_ERR_FORMAT;
}

int vol_churn(denc_session_t *s, uint64_t max_blocks, uint64_t *scrubbed) {
    return fs_scrub_free(&s->fs, max_blocks, scrubbed);
}
