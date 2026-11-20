#ifndef DENC_FS_H
#define DENC_FS_H

#include "disk.h"

/* Volume-internal layout (sector indices relative to the volume):
 *
 *   0          superblock slot A
 *   1          superblock slot B        (alternating, sequence-numbered)
 *   2 .. 2+W   two WAL slots
 *   ...        allocation bitmap
 *   ...        inode table
 *   ...        data blocks
 *
 * Everything except the two superblocks is journaled through the WAL, so a
 * crash at any instant leaves either the old or the new committed state —
 * never a torn write. All of it lives inside the ChaCha20 sector layer, so
 * the on-container bytes remain indistinguishable from random.
 */

#define FS_SUPER_SECTORS   2
#define FS_WAL_SLOTS       2
#define FS_WAL_SLOT_SECTORS 128                 /* 512 KiB per slot */
#define FS_WAL_SECTORS     (FS_WAL_SLOTS * FS_WAL_SLOT_SECTORS)
#define FS_META_RESERVED   (FS_SUPER_SECTORS + FS_WAL_SECTORS)

#define FS_MAGIC           0x46534445u           /* "FSDE" */
#define FS_SB_GEN          1u

/* WAL entry: old-block image followed by new-block image, each a full
 * sector. The slot's first sector is the commit header. */
#define FS_WAL_ENTRY_SECTORS 2
#define FS_WAL_HEADER_RESERVED 1
#define FS_WAL_MAX_ENTRIES ((FS_WAL_SLOT_SECTORS - FS_WAL_HEADER_RESERVED) \
                            / FS_WAL_ENTRY_SECTORS)   /* 63 entries */

typedef struct {
    uint32_t magic;
    uint32_t gen;
    uint64_t sequence;                /* monotonic; higher slot wins */
    uint64_t total_sectors;           /* volume size this FS was built on */
    uint64_t bitmap_start;
    uint64_t bitmap_sectors;
    uint64_t inode_start;
    uint64_t inode_sectors;
    uint64_t data_start;
    uint64_t data_sectors;
    uint64_t forbidden_from;          /* protected-mount: hidden tail */
    uint64_t forbidden_to;
    uint8_t  reserved[32];
    uint8_t  checksum[32];           /* SHA-256 over all preceding bytes */
} denc_super_t;

typedef struct {
    uint64_t extent_start[DENC_MAX_EXTENTS];   /* data-block indices */
    uint64_t extent_len[DENC_MAX_EXTENTS];
    uint64_t size;
    uint64_t mtime;
    uint32_t used;                              /* 0 = free inode */
    uint32_t name_len;
    char     name[DENC_NAME_MAX + 1];
    uint8_t  reserved[16];
} denc_inode_t;

#define FS_INODES_PER_SECTOR (DENC_SECTOR_SIZE / sizeof(denc_inode_t))

typedef struct {
    denc_disk_t *disk;
    denc_super_t sb;
    int          sb_loaded;

    /* dirty blocks pending in the current transaction: logical sector ->
     * old image / new image */
    uint64_t     dirty_sec[FS_WAL_MAX_ENTRIES];
    uint8_t     *old_img[FS_WAL_MAX_ENTRIES];
    uint8_t     *new_img[FS_WAL_MAX_ENTRIES];
    int          ndirty;
    uint64_t     sequence;
    int          wal_slot;             /* next slot to write */
} denc_fs_t;

int  fs_open(denc_fs_t *fs, denc_disk_t *d, uint64_t forbid_from,
             uint64_t forbid_to);
void fs_close(denc_fs_t *fs);

/* Format the volume (new container). */
int  fs_format(denc_fs_t *fs, denc_disk_t *d, uint64_t forbid_from,
               uint64_t forbid_to);

/* File operations. Each commits exactly one WAL transaction. */
int  fs_put(denc_fs_t *fs, const char *name, const uint8_t *data,
            uint64_t len);
int  fs_get(denc_fs_t *fs, const char *name, uint8_t **out, uint64_t *outlen);
int  fs_unlink(denc_fs_t *fs, const char *name);
int  fs_list(denc_fs_t *fs, FILE *out);
int  fs_stat(denc_fs_t *fs, const char *name, denc_inode_t *out);

/* Allocator / bitmap (also used by the churn routine). */
int  fs_alloc_blocks(denc_fs_t *fs, uint64_t count, uint64_t *start_out);
int  fs_free_blocks(denc_fs_t *fs, uint64_t start, uint64_t count);
int  fs_block_used(denc_fs_t *fs, uint64_t block, int *used);

/* Overwrite one logical sector through the transaction buffer. Reads the
 * old image on first touch. */
int  fs_write_logical(denc_fs_t *fs, uint64_t sector, const uint8_t *buf);
int  fs_read_logical(denc_fs_t *fs, uint64_t sector, uint8_t *buf);

int  fs_commit(denc_fs_t *fs);
int  fs_scrub_free(denc_fs_t *fs, uint64_t max_blocks, uint64_t *scrubbed);

#endif
