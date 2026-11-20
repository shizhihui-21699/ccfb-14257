#ifndef DENC_FORMAT_H
#define DENC_FORMAT_H

/* On-container format constants shared by the implementation and the
 * forensic analyzer. The analyzer includes this header but links none of
 * the implementation code, so it cannot accidentally "know" a password. */

#define DENC_FMT_SECTOR_SIZE   4096
#define DENC_FMT_HEADER_SLOTS  2
#define DENC_FMT_HEADER_RESERVED (DENC_FMT_HEADER_SLOTS * DENC_FMT_SECTOR_SIZE)
#define DENC_FMT_MAGIC         0x44454e43u  /* "DENC" */
#define DENC_FMT_VERSION       1u
#define DENC_FMT_NAME_MAX      127
#define DENC_FMT_MAX_EXTENTS   8

#define DENC_FMT_DOMAIN_OUTER  1u
#define DENC_FMT_DOMAIN_HIDDEN 2u
#define DENC_FMT_DOMAIN_HEADER 3u

/* Header slot byte layout. */
#define DENC_FMT_SALT_OFF   0
#define DENC_FMT_SALT_SIZE  32
#define DENC_FMT_ITER_OFF   32
#define DENC_FMT_CT_OFF     36
#define DENC_FMT_CT_LEN     (DENC_FMT_SECTOR_SIZE - DENC_FMT_CT_OFF)

#endif
