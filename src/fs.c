#include "fs.h"
#include "sha256.h"
#include "rand.h"
#include "common.h"

#include <time.h>
#include <inttypes.h>
#include <stdlib.h>

/* Test-only fault injection. DENC_CRASH_AT=<stage>:<count> aborts the process
 * at a WAL commit stage (1=after data entries, 2=after commit header,
 * 3=after home-sector apply), on the <count>-th matching commit. Default
 * build behavior is a no-op, simulating sudden power loss mid-transaction. */
static void crash_maybe(denc_fs_t *fs, int stage) {
    const char *env = getenv("DENC_CRASH_AT");
    if (!env) return;
    int want_stage = atoi(env);
    const char *colon = strchr(env, ':');
    int want_count = colon ? atoi(colon + 1) : 1;
    static int hits = 0;
    if (stage == want_stage) {
        hits++;
        if (hits >= want_count) {
            fprintf(stderr, "[fault] power loss stage %d: slot=%u seq=%llu"
                    " ne=%d targets=", stage,
                    (unsigned)(fs->wal_slot),
                    (unsigned long long)fs->sequence, fs->ndirty);
            for (int z = 0; z < fs->ndirty; z++)
                fprintf(stderr, "%llu ",
                        (unsigned long long)fs->dirty_sec[z]);
            fprintf(stderr, "\n");
            fflush(stderr);
            _Exit(99);
        }
    }
}

/* ---------- WAL on-disk header (first sector of each WAL slot) ---------- */

typedef struct {
    uint32_t magic;          /* 'W' 'A' 'L' 0 = 0x004c4157 */
    uint32_t nentries;
    uint64_t sequence;
    uint64_t target[FS_WAL_MAX_ENTRIES];   /* home sector per entry */
    uint8_t  checksum[32];  /* SHA-256 over target[] then old||new images */
} wal_hdr_t;

#define WAL_MAGIC 0x004c4157u

static uint64_t wal_slot_lbase(uint32_t slot) {
    return FS_SUPER_SECTORS + (uint64_t)slot * FS_WAL_SLOT_SECTORS;
}
static uint64_t wal_entry_lbase(uint32_t slot, int e) {
    return wal_slot_lbase(slot) + FS_WAL_HEADER_RESERVED
         + (uint64_t)e * FS_WAL_ENTRY_SECTORS;
}

/* ---------------- superblock helpers ---------------- */

static void sb_checksum(denc_super_t *sb) {
    sha256((const uint8_t *)sb, offsetof(denc_super_t, checksum),
           sb->checksum);
}

static int sb_valid(const denc_super_t *sb) {
    if (sb->magic != FS_MAGIC || sb->gen != FS_SB_GEN) return 0;
    uint8_t sum[32];
    sha256((const uint8_t *)sb, offsetof(denc_super_t, checksum), sum);
    return memcmp(sum, sb->checksum, 32) == 0;
}

static int sb_write(denc_fs_t *fs) {
    uint8_t buf[DENC_SECTOR_SIZE];
    memset(buf, 0, sizeof(buf));
    fs->sb.sequence = fs->sequence;
    sb_checksum(&fs->sb);
    memcpy(buf, &fs->sb, sizeof(fs->sb));
    int slot = (int)(fs->sequence & 1u);
    return disk_write_sector(fs->disk, (uint64_t)slot, buf);
}

/* ---------------- bitmap helpers ---------------- */

static void bitmap_set(uint8_t *bm, uint64_t block) {
    bm[block / 8] |= (uint8_t)(1u << (block & 7));
}
static void bitmap_clr(uint8_t *bm, uint64_t block) {
    bm[block / 8] &= (uint8_t)~(1u << (block & 7));
}

static int in_forbidden(denc_fs_t *fs, uint64_t block) {
    if (fs->sb.forbidden_to <= fs->sb.forbidden_from) return 0;
    return block >= fs->sb.forbidden_from && block < fs->sb.forbidden_to;
}

/* ---------------- transaction machinery ---------------- */

static int tx_find(denc_fs_t *fs, uint64_t sector) {
    for (int i = 0; i < fs->ndirty; i++)
        if (fs->dirty_sec[i] == sector) return i;
    return -1;
}

int fs_read_logical(denc_fs_t *fs, uint64_t sector, uint8_t *buf) {
    int i = tx_find(fs, sector);
    if (i >= 0) { memcpy(buf, fs->new_img[i], DENC_SECTOR_SIZE); return DENC_OK; }
    return disk_read_sector(fs->disk, sector, buf);
}

int fs_write_logical(denc_fs_t *fs, uint64_t sector, const uint8_t *buf) {
    int i = tx_find(fs, sector);
    if (i >= 0) { memcpy(fs->new_img[i], buf, DENC_SECTOR_SIZE); return DENC_OK; }
    if (fs->ndirty >= FS_WAL_MAX_ENTRIES)
        return DENC_ERR_NOSPACE;      /* caller must commit first */
    int n = fs->ndirty++;
    fs->dirty_sec[n] = sector;
    fs->old_img[n] = calloc(1, DENC_SECTOR_SIZE);
    fs->new_img[n] = calloc(1, DENC_SECTOR_SIZE);
    if (!fs->old_img[n] || !fs->new_img[n]) return DENC_ERR_IO;
    int rc = disk_read_sector(fs->disk, sector, fs->old_img[n]);
    if (rc != DENC_OK) return rc;
    memcpy(fs->new_img[n], buf, DENC_SECTOR_SIZE);
    return DENC_OK;
}

static int wal_apply(denc_fs_t *fs, uint32_t slot, int use_new) {
    uint8_t hbuf[DENC_SECTOR_SIZE];
    int rc = disk_read_sector(fs->disk, wal_slot_lbase(slot), hbuf);
    if (rc != DENC_OK) return rc;
    wal_hdr_t wh;
    memcpy(&wh, hbuf, sizeof(wh));
    if (wh.magic != WAL_MAGIC || wh.nentries == 0 ||
        wh.nentries > FS_WAL_MAX_ENTRIES)
        return DENC_OK;                 /* empty / torn header: nothing to do */

    /* verify checksum: H(target[] || old_image || new_image per entry) */
    sha256_ctx sc; sha256_init(&sc);
    sha256_update(&sc, (const uint8_t *)wh.target,
                  wh.nentries * sizeof(uint64_t));
    uint8_t img[DENC_SECTOR_SIZE];
    for (uint32_t e = 0; e < wh.nentries; e++) {
        uint64_t lbase = wal_entry_lbase(slot, (int)e);
        int r2 = disk_read_sector(fs->disk, lbase, img);
        if (r2 != DENC_OK) return r2;
        sha256_update(&sc, img, DENC_SECTOR_SIZE);            /* old */
        r2 = disk_read_sector(fs->disk, lbase + 1, img);
        if (r2 != DENC_OK) return r2;
        sha256_update(&sc, img, DENC_SECTOR_SIZE);            /* new */
    }
    uint8_t sum[32];
    sha256_final(&sc, sum);
    if (memcmp(sum, wh.checksum, 32) != 0)
        return DENC_OK;                 /* torn log: discard, keep on-disk */

    for (uint32_t e = 0; e < wh.nentries; e++) {
        uint64_t lbase = wal_entry_lbase(slot, (int)e);
        /* entry layout: full old image, then full new image; target index
         * lives in the WAL header */
        if (!use_new) {
            rc = disk_read_sector(fs->disk, lbase, img);          /* old */
        } else {
            rc = disk_read_sector(fs->disk, lbase + 1, img);      /* new */
        }
        if (rc != DENC_OK) return rc;
        rc = disk_write_sector(fs->disk, wh.target[e], img);
        if (rc != DENC_OK) return rc;
    }
    return DENC_OK;
}

/* Redo recovery: pick the valid WAL slot with the highest sequence. */
static int wal_recover(denc_fs_t *fs) {
    uint8_t hbuf[DENC_SECTOR_SIZE];
    wal_hdr_t cand[FS_WAL_SLOTS];
    int have[FS_WAL_SLOTS] = {0, 0};
    for (int s = 0; s < FS_WAL_SLOTS; s++) {
        if (disk_read_sector(fs->disk, wal_slot_lbase((uint32_t)s), hbuf)
            != DENC_OK) continue;
        memcpy(&cand[s], hbuf, sizeof(wal_hdr_t));
        if (cand[s].magic == WAL_MAGIC && cand[s].nentries > 0 &&
            cand[s].nentries <= FS_WAL_MAX_ENTRIES)
            have[s] = 1;
    }
    if (!have[0] && !have[1]) return DENC_OK;
    int pick;
    if (have[0] && have[1])
        pick = cand[0].sequence >= cand[1].sequence ? 0 : 1;
    else
        pick = have[0] ? 0 : 1;
    int rc = wal_apply(fs, (uint32_t)pick, 1);
    if (rc != DENC_OK) return rc;
    if (disk_flush(fs->disk) != DENC_OK) return DENC_ERR_IO;

    /* The replayed transaction is now durable in its home sectors. Make the
     * superblock catch up to the WAL sequence and retire the log, so the
     * recovered state is itself crash-consistent from this point on. */
    fs->sequence = cand[pick].sequence;
    fs->wal_slot = (pick + 1) % FS_WAL_SLOTS;
    rc = sb_write(fs);
    if (rc != DENC_OK) return rc;
    if (disk_flush(fs->disk) != DENC_OK) return DENC_ERR_IO;

    uint8_t zero[DENC_SECTOR_SIZE];
    memset(zero, 0, sizeof(zero));
    disk_write_sector(fs->disk, wal_slot_lbase((uint32_t)pick), zero);
    disk_flush(fs->disk);
    return DENC_OK;
}

int fs_commit(denc_fs_t *fs) {
    if (fs->ndirty == 0) return DENC_OK;
    if (fs->ndirty > FS_WAL_MAX_ENTRIES) return DENC_ERR_NOSPACE;

    uint32_t slot = (uint32_t)fs->wal_slot;
    uint64_t hbase = wal_slot_lbase(slot);

    /* 1. checksum over target indices then old/new sector images */
    sha256_ctx sc; sha256_init(&sc);
    uint8_t hdr[DENC_SECTOR_SIZE];
    memset(hdr, 0, sizeof(hdr));
    for (int e = 0; e < fs->ndirty; e++) {
        sha256_update(&sc, (const uint8_t *)&fs->dirty_sec[e], 8);
    }
    for (int e = 0; e < fs->ndirty; e++) {
        sha256_update(&sc, fs->old_img[e], DENC_SECTOR_SIZE);
        sha256_update(&sc, fs->new_img[e], DENC_SECTOR_SIZE);
    }
    uint8_t sum[32]; sha256_final(&sc, sum);
    wal_hdr_t wh;
    memset(&wh, 0, sizeof(wh));
    wh.magic = WAL_MAGIC;
    wh.nentries = (uint32_t)fs->ndirty;
    wh.sequence = fs->sequence + 1;
    for (int e = 0; e < fs->ndirty; e++) wh.target[e] = fs->dirty_sec[e];
    memcpy(wh.checksum, sum, 32);

    /* 2. write full old/new images, then the commit header last */
    int rc;
    for (int e = 0; e < fs->ndirty; e++) {
        uint64_t lbase = wal_entry_lbase(slot, e);
        if ((rc = disk_write_sector(fs->disk, lbase,
                                    fs->old_img[e])) != DENC_OK)
            goto fail;
        if ((rc = disk_write_sector(fs->disk, lbase + 1,
                                    fs->new_img[e])) != DENC_OK)
            goto fail;
    }
    if ((rc = disk_flush(fs->disk)) != DENC_OK) goto fail;
    crash_maybe(fs, 1);   /* power loss after entries, before commit header */

    /* 3. commit header: its durable appearance makes the transaction valid */
    memcpy(hdr, &wh, sizeof(wh));
    if ((rc = disk_write_sector(fs->disk, hbase, hdr)) != DENC_OK) goto fail;
    if ((rc = disk_flush(fs->disk)) != DENC_OK) goto fail;
    crash_maybe(fs, 2);   /* power loss after durable commit, before apply */

    /* 4. apply new images to their home sectors */
    for (int e = 0; e < fs->ndirty; e++) {
        rc = disk_write_sector(fs->disk, fs->dirty_sec[e],
                               fs->new_img[e]);
        if (rc != DENC_OK) goto fail;
    }
    if ((rc = disk_flush(fs->disk)) != DENC_OK) goto fail;
    crash_maybe(fs, 3);   /* power loss after apply, before superblock advance */

    /* 5. advance superblock (alternating slots), then invalidate this WAL */
    fs->sequence++;
    if ((rc = sb_write(fs)) != DENC_OK) goto fail;
    if ((rc = disk_flush(fs->disk)) != DENC_OK) goto fail;

    memset(hdr, 0, sizeof(hdr));
    disk_write_sector(fs->disk, hbase, hdr);
    disk_flush(fs->disk);

    fs->wal_slot = (fs->wal_slot + 1) % FS_WAL_SLOTS;
    for (int e = 0; e < fs->ndirty; e++) {
        denc_explicit_bzero(fs->old_img[e], DENC_SECTOR_SIZE);
        denc_explicit_bzero(fs->new_img[e], DENC_SECTOR_SIZE);
        free(fs->old_img[e]); free(fs->new_img[e]);
    }
    fs->ndirty = 0;
    return DENC_OK;
fail:
    return rc;
}

/* ---------------- format / open / close ---------------- */

static void layout(denc_super_t *sb, uint64_t total,
                   uint64_t forbid_from, uint64_t forbid_to) {
    sb->total_sectors = total;
    sb->bitmap_start = FS_META_RESERVED;
    uint64_t usable = total - FS_META_RESERVED;
    uint64_t bm_bytes = (usable + 7) / 8;
    sb->bitmap_sectors = (bm_bytes + DENC_SECTOR_SIZE - 1) / DENC_SECTOR_SIZE;
    if (sb->bitmap_sectors < 1) sb->bitmap_sectors = 1;
    sb->inode_start = sb->bitmap_start + sb->bitmap_sectors;
    /* one inode sector per ~64 data sectors keeps the inode table modest */
    uint64_t inode_sec = (total / 64) + 1;
    if (inode_sec < 2) inode_sec = 2;
    sb->inode_sectors = inode_sec;
    sb->data_start = sb->inode_start + sb->inode_sectors;
    if (sb->data_start >= total) {
        sb->data_start = total - 1;
        sb->data_sectors = 0;
    } else {
        sb->data_sectors = total - sb->data_start;
    }
    sb->forbidden_from = forbid_from;
    sb->forbidden_to = forbid_to;
}

int fs_format(denc_fs_t *fs, denc_disk_t *d, uint64_t forbid_from,
              uint64_t forbid_to) {
    memset(fs, 0, sizeof(*fs));
    fs->disk = d;
    fs->sequence = 1;
    fs->wal_slot = 0;

    denc_super_t *sb = &fs->sb;
    memset(sb, 0, sizeof(*sb));
    sb->magic = FS_MAGIC;
    sb->gen = FS_SB_GEN;
    layout(sb, d->vol_sectors, forbid_from, forbid_to);

    if (forbid_to > d->vol_sectors) return DENC_ERR_USAGE;

    /* Randomize every volume sector first: free space must not be zeros. */
    uint8_t buf[DENC_SECTOR_SIZE];
    for (uint64_t s = 0; s < d->vol_sectors; s++) {
        if (denc_random(buf, DENC_SECTOR_SIZE) != DENC_OK)
            return DENC_ERR_CRYPTO;
        int rc = disk_write_sector(d, s, buf);
        if (rc != DENC_OK) return rc;
    }
    if (disk_flush(d) != DENC_OK) return DENC_ERR_IO;

    /* Zeroed bitmap and inode table, committed in batches that fit in one
     * WAL transaction (these are fresh structure writes, so batching is
     * crash-safe: recovery either completes a batch or leaves the prior
     * committed state). */
    uint64_t bm_bytes = sb->bitmap_sectors * DENC_SECTOR_SIZE;
    uint8_t *bm = calloc(1, bm_bytes);
    if (!bm) return DENC_ERR_IO;
    for (uint64_t s = 0; s < sb->bitmap_sectors; s++) {
        int rc = fs_write_logical(fs, sb->bitmap_start + s,
                                  bm + s * DENC_SECTOR_SIZE);
        if (rc != DENC_OK) { free(bm); return rc; }
    }
    free(bm);
    if (fs->ndirty) {
        int rc = fs_commit(fs);
        if (rc != DENC_OK) return rc;
    }
    memset(buf, 0, sizeof(buf));
    for (uint64_t s = 0; s < sb->inode_sectors; s++) {
        int rc = fs_write_logical(fs, sb->inode_start + s, buf);
        if (rc != DENC_OK) return rc;
        if (fs->ndirty >= FS_WAL_MAX_ENTRIES) {
            rc = fs_commit(fs);
            if (rc != DENC_OK) return rc;
        }
    }
    int rc = fs_commit(fs);
    if (rc != DENC_OK) return rc;

    /* Both superblock slots get a valid copy. */
    sb->sequence = fs->sequence;
    sb_checksum(sb);
    uint8_t sbuf[DENC_SECTOR_SIZE];
    memset(sbuf, 0, sizeof(sbuf));
    memcpy(sbuf, sb, sizeof(*sb));
    if ((rc = disk_write_sector(d, 0, sbuf)) != DENC_OK) return rc;
    sb->sequence++;
    fs->sequence = sb->sequence;
    sb_checksum(sb);
    memcpy(sbuf, sb, sizeof(*sb));
    return disk_write_sector(d, 1, sbuf);
}

int fs_open(denc_fs_t *fs, denc_disk_t *d, uint64_t forbid_from,
            uint64_t forbid_to) {
    memset(fs, 0, sizeof(*fs));
    fs->disk = d;

    denc_super_t slots[2];
    uint8_t buf[DENC_SECTOR_SIZE];
    int valid[2] = {0, 0};
    for (int s = 0; s < 2; s++) {
        int rc = disk_read_sector(d, (uint64_t)s, buf);
        if (rc != DENC_OK) return rc;
        memcpy(&slots[s], buf, sizeof(denc_super_t));
        if (sb_valid(&slots[s])) valid[s] = 1;
    }
    if (!valid[0] && !valid[1]) return DENC_ERR_FORMAT;
    int pick;
    if (valid[0] && valid[1])
        pick = slots[0].sequence > slots[1].sequence ? 0 : 1;
    else
        pick = valid[0] ? 0 : 1;
    fs->sb = slots[pick];
    fs->sequence = fs->sb.sequence;
    fs->wal_slot = (int)((fs->sequence + 1) % FS_WAL_SLOTS);

    /* Protected mount narrows the forbidden window; never widens it. */
    if (forbid_to > forbid_from) {
        if (fs->sb.forbidden_to <= fs->sb.forbidden_from) {
            fs->sb.forbidden_from = forbid_from;
            fs->sb.forbidden_to = forbid_to;
        } else {
            if (forbid_from < fs->sb.forbidden_from)
                fs->sb.forbidden_from = forbid_from;
            if (forbid_to > fs->sb.forbidden_to)
                fs->sb.forbidden_to = forbid_to;
        }
    }

    return wal_recover(fs);
}

void fs_close(denc_fs_t *fs) {
    if (fs->ndirty) fs_commit(fs);
    for (int e = 0; e < fs->ndirty; e++) {
        free(fs->old_img[e]); free(fs->new_img[e]);
    }
    denc_explicit_bzero(fs, sizeof(*fs));
}

/* ---------------- allocator ---------------- */

int fs_block_used(denc_fs_t *fs, uint64_t block, int *used) {
    uint8_t buf[DENC_SECTOR_SIZE];
    uint64_t bm_byte_off = block / 8;
    uint64_t sec = fs->sb.bitmap_start + bm_byte_off / DENC_SECTOR_SIZE;
    int rc = fs_read_logical(fs, sec, buf);
    if (rc != DENC_OK) return rc;
    *used = (buf[bm_byte_off % DENC_SECTOR_SIZE] >> (block & 7)) & 1;
    return DENC_OK;
}

static int mark_range(denc_fs_t *fs, uint64_t start, uint64_t count,
                      int used) {
    uint8_t buf[DENC_SECTOR_SIZE];
    for (uint64_t b = start; b < start + count; b++) {
        uint64_t byte_off = b / 8;
        uint64_t sec = fs->sb.bitmap_start + byte_off / DENC_SECTOR_SIZE;
        int rc = fs_read_logical(fs, sec, buf);
        if (rc != DENC_OK) return rc;
        if (used) bitmap_set(buf, b); else bitmap_clr(buf, b);
        rc = fs_write_logical(fs, sec, buf);
        if (rc != DENC_OK) return rc;
    }
    return DENC_OK;
}

int fs_alloc_blocks(denc_fs_t *fs, uint64_t count, uint64_t *start_out) {
    if (count == 0) return DENC_ERR_USAGE;
    uint64_t n = fs->sb.data_sectors;
    uint64_t run = 0, best = UINT64_MAX;
    /* first-fit contiguous run, skipping the forbidden (hidden) tail */
    for (uint64_t b = 0; b < n; b++) {
        if (in_forbidden(fs, b)) { run = 0; continue; }
        int used;
        int rc = fs_block_used(fs, b, &used);
        if (rc != DENC_OK) return rc;
        if (used) { run = 0; continue; }
        run++;
        if (run >= count) { best = b - count + 1; break; }
    }
    if (best == UINT64_MAX) return DENC_ERR_NOSPACE;
    int rc = mark_range(fs, best, count, 1);
    if (rc != DENC_OK) return rc;
    *start_out = best;
    return DENC_OK;
}

int fs_free_blocks(denc_fs_t *fs, uint64_t start, uint64_t count) {
    return mark_range(fs, start, count, 0);
}

/* ---------------- inode helpers ---------------- */

static int inode_locate(denc_fs_t *fs, uint32_t idx, uint64_t *sec,
                        uint32_t *off) {
    if (idx >= fs->sb.inode_sectors * FS_INODES_PER_SECTOR)
        return DENC_ERR_NOSPACE;
    *sec = fs->sb.inode_start + idx / FS_INODES_PER_SECTOR;
    *off = idx % FS_INODES_PER_SECTOR;
    return DENC_OK;
}

static int inode_read(denc_fs_t *fs, uint32_t idx, denc_inode_t *ino) {
    uint64_t sec; uint32_t off;
    int rc = inode_locate(fs, idx, &sec, &off);
    if (rc != DENC_OK) return rc;
    uint8_t buf[DENC_SECTOR_SIZE];
    if ((rc = fs_read_logical(fs, sec, buf)) != DENC_OK) return rc;
    memcpy(ino, buf + off * sizeof(denc_inode_t), sizeof(*ino));
    return DENC_OK;
}

static int inode_write(denc_fs_t *fs, uint32_t idx, const denc_inode_t *ino) {
    uint64_t sec; uint32_t off;
    int rc = inode_locate(fs, idx, &sec, &off);
    if (rc != DENC_OK) return rc;
    uint8_t buf[DENC_SECTOR_SIZE];
    if ((rc = fs_read_logical(fs, sec, buf)) != DENC_OK) return rc;
    memcpy(buf + off * sizeof(denc_inode_t), ino, sizeof(*ino));
    return fs_write_logical(fs, sec, buf);
}

static int inode_find(denc_fs_t *fs, const char *name, uint32_t *idx,
                      denc_inode_t *ino, int *found) {
    uint32_t total = (uint32_t)(fs->sb.inode_sectors * FS_INODES_PER_SECTOR);
    size_t nlen = strlen(name);
    if (nlen > DENC_NAME_MAX) return DENC_ERR_USAGE;
    *found = 0;
    for (uint32_t i = 0; i < total; i++) {
        denc_inode_t cur;
        int rc = inode_read(fs, i, &cur);
        if (rc != DENC_OK) return rc;
        if (cur.used && cur.name_len == nlen &&
            memcmp(cur.name, name, nlen) == 0) {
            if (idx) *idx = i;
            if (ino) *ino = cur;
            *found = 1;
            return DENC_OK;
        }
    }
    return DENC_OK;
}

/* ---------------- file operations ---------------- */

static uint64_t blocks_for(uint64_t len) {
    return len == 0 ? 0 : (len + DENC_SECTOR_SIZE - 1) / DENC_SECTOR_SIZE;
}

/* Reserve a couple of WAL slots in every transaction for bitmap and inode
 * sectors, which are touched alongside the data blocks. */
#define FS_TX_DATA_BUDGET (FS_WAL_MAX_ENTRIES - 2)

int fs_put(denc_fs_t *fs, const char *name, const uint8_t *data,
           uint64_t len) {
    if (strlen(name) > DENC_NAME_MAX) return DENC_ERR_USAGE;
    uint32_t idx; denc_inode_t existing; int found;
    int rc = inode_find(fs, name, &idx, &existing, &found);
    if (rc != DENC_OK) return rc;

    /* Number of data blocks, capped so extents fit the inode. */
    uint64_t need = blocks_for(len);
    uint64_t max_blocks = (uint64_t)FS_TX_DATA_BUDGET * DENC_MAX_EXTENTS;
    if (need > max_blocks) return DENC_ERR_NOSPACE;

    denc_inode_t ino;
    memset(&ino, 0, sizeof(ino));
    if (found) {
        /* free the old inode's extents and its inode slot in one tx */
        for (int e = 0; e < DENC_MAX_EXTENTS; e++) {
            if (existing.extent_len[e]) {
                rc = fs_free_blocks(fs, existing.extent_start[e],
                                    existing.extent_len[e]);
                if (rc != DENC_OK) return rc;
            }
        }
        memset(&existing, 0, sizeof(existing));
        if ((rc = inode_write(fs, idx, &existing)) != DENC_OK) return rc;
        if ((rc = fs_commit(fs)) != DENC_OK) return rc;
    } else {
        uint32_t total = (uint32_t)(fs->sb.inode_sectors *
                                    FS_INODES_PER_SECTOR);
        for (idx = 0; idx < total; idx++) {
            denc_inode_t cur;
            if ((rc = inode_read(fs, idx, &cur)) != DENC_OK) return rc;
            if (!cur.used) break;
        }
        if (idx == total) return DENC_ERR_NOSPACE;
    }

    ino.used = 1;
    ino.size = len;
    ino.name_len = (uint32_t)strlen(name);
    memcpy(ino.name, name, ino.name_len);
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ino.mtime = (uint64_t)ts.tv_sec;

    /* allocate every extent up front (bitmap commits stay small because each
     * extent is at most FS_TX_DATA_BUDGET blocks) */
    uint64_t left = need, next_extent = 0;
    while (left > 0) {
        if (next_extent >= DENC_MAX_EXTENTS) { rc = DENC_ERR_NOSPACE; goto fail; }
        uint64_t chunk = left;
        if (chunk > FS_TX_DATA_BUDGET) chunk = FS_TX_DATA_BUDGET;
        uint64_t start;
        rc = fs_alloc_blocks(fs, chunk, &start);
        if (rc != DENC_OK) goto fail;
        ino.extent_start[next_extent] = start;
        ino.extent_len[next_extent] = chunk;
        next_extent++;
        left -= chunk;
        if (fs->ndirty > 0 && (rc = fs_commit(fs)) != DENC_OK) goto fail;
    }

    /* write data in atomic batches of FS_TX_DATA_BUDGET blocks */
    uint64_t b = 0;
    while (b < need) {
        uint64_t batch = need - b;
        if (batch > FS_TX_DATA_BUDGET) batch = FS_TX_DATA_BUDGET;
        for (uint64_t j = 0; j < batch; j++) {
            uint64_t rel = b + j, abs_block = UINT64_MAX, r2 = rel;
            for (int e = 0; e < DENC_MAX_EXTENTS; e++) {
                if (r2 < ino.extent_len[e]) {
                    abs_block = ino.extent_start[e] + r2;
                    break;
                }
                r2 -= ino.extent_len[e];
            }
            if (abs_block == UINT64_MAX) { rc = DENC_ERR_FORMAT; goto fail; }

            uint8_t buf[DENC_SECTOR_SIZE];
            uint64_t off = rel * DENC_SECTOR_SIZE;
            uint64_t take = len - off;
            if (take > DENC_SECTOR_SIZE) take = DENC_SECTOR_SIZE;
            memset(buf, 0, sizeof(buf));
            memcpy(buf, data + off, take);   /* tail zeroed, not stale */
            rc = fs_write_logical(fs, fs->sb.data_start + abs_block, buf);
            if (rc != DENC_OK) goto fail;
        }
        if ((rc = fs_commit(fs)) != DENC_OK) goto fail;
        b += batch;
    }

    rc = inode_write(fs, idx, &ino);
    if (rc != DENC_OK) return rc;
    return fs_commit(fs);

fail: {
    /* on-disk state is always the last committed state; release any extents
     * we allocated but never published in an inode. Preserve the original
     * error code rather than letting cleanup overwrite it. */
    int saved_rc = rc;
    for (uint64_t e = 0; e < next_extent; e++) {
        if (ino.extent_len[e])
            fs_free_blocks(fs, ino.extent_start[e], ino.extent_len[e]);
    }
    if (fs->ndirty > 0) fs_commit(fs);
    return saved_rc;
}
}

int fs_get(denc_fs_t *fs, const char *name, uint8_t **out, uint64_t *outlen) {
    denc_inode_t ino; int found;
    int rc = inode_find(fs, name, NULL, &ino, &found);
    if (rc != DENC_OK) return rc;
    if (!found) return DENC_ERR_NOENT;
    uint8_t *buf = malloc(ino.size ? ino.size : 1);
    if (!buf) return DENC_ERR_IO;
    uint64_t copied = 0;
    uint8_t sec[DENC_SECTOR_SIZE];
    for (int e = 0; e < DENC_MAX_EXTENTS; e++) {
        for (uint64_t b = 0; b < ino.extent_len[e]; b++) {
            rc = fs_read_logical(fs, fs->sb.data_start +
                                 ino.extent_start[e] + b, sec);
            if (rc != DENC_OK) { free(buf); return rc; }
            uint64_t take = ino.size - copied;
            if (take > DENC_SECTOR_SIZE) take = DENC_SECTOR_SIZE;
            memcpy(buf + copied, sec, take);
            copied += take;
        }
    }
    *out = buf;
    *outlen = ino.size;
    return DENC_OK;
}

int fs_unlink(denc_fs_t *fs, const char *name) {
    uint32_t idx; denc_inode_t ino; int found;
    int rc = inode_find(fs, name, &idx, &ino, &found);
    if (rc != DENC_OK) return rc;
    if (!found) return DENC_ERR_NOENT;
    for (int e = 0; e < DENC_MAX_EXTENTS; e++) {
        if (ino.extent_len[e]) {
            rc = fs_free_blocks(fs, ino.extent_start[e],
                                ino.extent_len[e]);
            if (rc != DENC_OK) return rc;
        }
    }
    memset(&ino, 0, sizeof(ino));
    if ((rc = inode_write(fs, idx, &ino)) != DENC_OK) return rc;
    return fs_commit(fs);
}

int fs_stat(denc_fs_t *fs, const char *name, denc_inode_t *out) {
    int found;
    int rc = inode_find(fs, name, NULL, out, &found);
    if (rc != DENC_OK) return rc;
    return found ? DENC_OK : DENC_ERR_NOENT;
}

int fs_list(denc_fs_t *fs, FILE *out) {
    uint32_t total = (uint32_t)(fs->sb.inode_sectors * FS_INODES_PER_SECTOR);
    for (uint32_t i = 0; i < total; i++) {
        denc_inode_t ino;
        int rc = inode_read(fs, i, &ino);
        if (rc != DENC_OK) return rc;
        if (ino.used)
            fprintf(out, "%10llu  %s\n", (unsigned long long)ino.size,
                    ino.name);
    }
    return DENC_OK;
}

/* ---------------- free-space scrub (deniability churn) ---------------- */

int fs_scrub_free(denc_fs_t *fs, uint64_t max_blocks, uint64_t *scrubbed) {
    uint64_t done = 0;
    uint8_t buf[DENC_SECTOR_SIZE];
    for (uint64_t b = 0; b < fs->sb.data_sectors && done < max_blocks; b++) {
        if (in_forbidden(fs, b)) continue;
        int used;
        int rc = fs_block_used(fs, b, &used);
        if (rc != DENC_OK) return rc;
        if (used) continue;
        if (denc_random(buf, DENC_SECTOR_SIZE) != DENC_OK)
            return DENC_ERR_CRYPTO;
        /* direct sector write: free blocks hold no metadata, so no WAL
         * entry is needed; flush at the end keeps recovery simple */
        rc = disk_write_sector(fs->disk, fs->sb.data_start + b, buf);
        if (rc != DENC_OK) return rc;
        done++;
        if ((done & 15u) == 0 && disk_flush(fs->disk) != DENC_OK)
            return DENC_ERR_IO;
    }
    if (disk_flush(fs->disk) != DENC_OK) return DENC_ERR_IO;
    if (scrubbed) *scrubbed = done;
    return DENC_OK;
}
