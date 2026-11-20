#include "vol.h"
#include "rand.h"
#include "common.h"

#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <inttypes.h>

static void usage(void) {
    fprintf(stderr,
"denc - plausibly deniable encrypted container\n\n"
"  denc create  [-k] [-H hidden-sectors] -s size  -p pwfile  container\n"
"  denc open    [-k] [--hidden] [-p pwfile] container ls\n"
"  denc open    [-k] [-p pwfile] container put hostfile name\n"
"  denc open    [-k] [-p pwfile] container get name hostfile\n"
"  denc open    [-k] [-p pwfile] container rm name\n"
"  denc open    [-k] [-p pwfile] container info\n"
"  denc open    [-k] [-p pwfile] container churn [max-blocks]\n"
"  denc chpass  -p oldpw -P newpw container\n\n"
"  -k   preserve container mtime/atime across the session\n"
"  size suffixes: K M G (binary); password read verbatim from pwfile\n");
}

static int read_file_all(const char *path, uint8_t **buf, size_t *len) {
    FILE *fp = fopen(path, "rb");
    if (!fp) return DENC_ERR_IO;
    fseek(fp, 0, SEEK_END);
    long n = ftell(fp);
    if (n < 0) { fclose(fp); return DENC_ERR_IO; }
    rewind(fp);
    *buf = malloc((size_t)n + 1);
    if (!*buf) { fclose(fp); return DENC_ERR_IO; }
    if (fread(*buf, 1, (size_t)n, fp) != (size_t)n) {
        free(*buf); fclose(fp); return DENC_ERR_IO;
    }
    fclose(fp);
    (*buf)[n] = 0;
    *len = (size_t)n;
    return DENC_OK;
}

static int read_password(const char *pwfile, uint8_t **pw, size_t *pwlen) {
    if (pwfile) return read_file_all(pwfile, pw, pwlen);
    /* no -p: read from stdin without echo is TTY-specific; keep it simple */
    size_t cap = 4096, n = 0;
    *pw = malloc(cap);
    if (!*pw) return DENC_ERR_IO;
    int c;
    while ((c = fgetc(stdin)) != EOF && c != '\n') {
        if (n + 1 >= cap) { cap *= 2; *pw = realloc(*pw, cap); }
        (*pw)[n++] = (uint8_t)c;
    }
    *pwlen = n;
    return DENC_OK;
}

static uint64_t parse_size(const char *s) {
    char *end;
    uint64_t v = strtoull(s, &end, 10);
    uint64_t mult = 1;
    if (*end == 'K' || *end == 'k') mult = 1ULL << 10;
    else if (*end == 'M' || *end == 'm') mult = 1ULL << 20;
    else if (*end == 'G' || *end == 'g') mult = 1ULL << 30;
    else if (*end != 0) return 0;
    if (mult > 1 && end[1] != 0) return 0;
    v *= mult;
    return v;
}

static int cmd_create(int argc, char **argv) {
    const char *pwfile = NULL;
    uint64_t size_bytes = 0, hidden_bytes = 0;
    int keep_mtime = 0;
    int i;
    for (i = 0; i < argc; i++) {
        if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) pwfile = argv[++i];
        else if (strcmp(argv[i], "-s") == 0 && i + 1 < argc) {
            size_bytes = parse_size(argv[++i]);
        } else if (strcmp(argv[i], "-H") == 0 && i + 1 < argc) {
            hidden_bytes = parse_size(argv[++i]);
        } else if (strcmp(argv[i], "-k") == 0) keep_mtime = 1;
        else break;
    }
    if (i != argc - 1 || size_bytes == 0 ||
        size_bytes % DENC_SECTOR_SIZE != 0) {
        usage();
        return DENC_ERR_USAGE;
    }
    uint8_t *pw; size_t pwlen;
    int rc = read_password(pwfile, &pw, &pwlen);
    if (rc != DENC_OK) return rc;
    uint64_t total = size_bytes / DENC_SECTOR_SIZE;
    uint64_t hidden = hidden_bytes / DENC_SECTOR_SIZE;
    rc = vol_create(argv[i], total, pw, pwlen, hidden, keep_mtime);
    if (rc == DENC_OK)
        printf("created %s (%" PRIu64 " sectors, %s)\n", argv[i], total,
               hidden ? "outer + hidden" : "outer only");
    denc_explicit_bzero(pw, pwlen);
    free(pw);
    return rc;
}

static int cmd_open(int argc, char **argv) {
    const char *pwfile = NULL;
    int keep_mtime = 0, use_hidden = 0, i;
    for (i = 0; i < argc; i++) {
        if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) pwfile = argv[++i];
        else if (strcmp(argv[i], "-k") == 0) keep_mtime = 1;
        else if (strcmp(argv[i], "--hidden") == 0) use_hidden = 1;
        else break;
    }
    if (i + 1 >= argc) { usage(); return DENC_ERR_USAGE; }
    const char *path = argv[i++];
    const char *sub = argv[i++];

    uint8_t *pw; size_t pwlen;
    int rc = read_password(pwfile, &pw, &pwlen);
    if (rc != DENC_OK) return rc;

    denc_session_t sess;
    rc = use_hidden ? vol_open_hidden(&sess, path, pw, pwlen, keep_mtime)
                    : vol_open(&sess, path, pw, pwlen, keep_mtime);
    denc_explicit_bzero(pw, pwlen);
    free(pw);
    if (rc != DENC_OK) return rc;

    if (!sub || strcmp(sub, "ls") == 0) {
        rc = fs_list(&sess.fs, stdout);
    } else if (strcmp(sub, "info") == 0) {
        denc_disk_t *d = &sess.disk;
        denc_super_t *sb = &sess.fs.sb;
        printf("mounted       : %s volume\n",
               sess.is_hidden ? "HIDDEN" : "outer (protected)");
        printf("container     : %" PRIu64 " sectors (%.2f MiB)\n",
               d->total_sectors,
               (double)d->total_sectors * DENC_SECTOR_SIZE / 1048576.0);
        printf("volume region : %" PRIu64 " sectors\n", d->vol_sectors);
        printf("data blocks   : %" PRIu64 " (free window starts at %" PRIu64
               ")\n", sb->data_sectors, sb->data_start);
        if (sb->forbidden_to > sb->forbidden_from)
            printf("protected tail: blocks %" PRIu64 "..%" PRIu64
                   " (%" PRIu64 " sectors)\n",
                   sb->forbidden_from, sb->forbidden_to - 1,
                   sb->forbidden_to - sb->forbidden_from);
        else
            printf("protected tail: none\n");
        rc = DENC_OK;
    } else if (strcmp(sub, "put") == 0 && i + 1 < argc) {
        uint8_t *data; size_t dlen;
        rc = read_file_all(argv[i], &data, &dlen);
        if (rc != DENC_OK) goto done;
        rc = fs_put(&sess.fs, argv[i + 1], data, dlen);
        denc_explicit_bzero(data, dlen);
        free(data);
    } else if (strcmp(sub, "get") == 0 && i + 1 < argc) {
        uint8_t *data; uint64_t dlen;
        rc = fs_get(&sess.fs, argv[i], &data, &dlen);
        if (rc != DENC_OK) goto done;
        FILE *o = fopen(argv[i + 1], "wb");
        if (!o) { rc = DENC_ERR_IO; free(data); goto done; }
        fwrite(data, 1, dlen, o);
        fclose(o);
        denc_explicit_bzero(data, dlen);
        free(data);
    } else if (strcmp(sub, "rm") == 0 && i < argc) {
        rc = fs_unlink(&sess.fs, argv[i]);
    } else if (strcmp(sub, "churn") == 0) {
        uint64_t max_blocks = sess.fs.sb.data_sectors;
        if (i < argc) max_blocks = strtoull(argv[i], NULL, 10);
        uint64_t scrubbed = 0;
        rc = vol_churn(&sess, max_blocks, &scrubbed);
        if (rc == DENC_OK)
            printf("scrubbed %" PRIu64 " free blocks\n", scrubbed);
    } else {
        usage();
        rc = DENC_ERR_USAGE;
    }
done:
    vol_close(&sess);
    return rc;
}

static int cmd_chpass(int argc, char **argv) {
    const char *oldf = NULL, *newf = NULL;
    const char *path = NULL;
    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) oldf = argv[++i];
        else if (strcmp(argv[i], "-P") == 0 && i + 1 < argc) newf = argv[++i];
        else if (!path) path = argv[i];
    }
    if (!oldf || !newf || !path) { usage(); return DENC_ERR_USAGE; }
    uint8_t *opw, *npw; size_t olen, nlen;
    int rc = read_file_all(oldf, &opw, &olen);
    if (rc != DENC_OK) return rc;
    rc = read_file_all(newf, &npw, &nlen);
    if (rc != DENC_OK) { free(opw); return rc; }
    rc = vol_chpass(path, opw, olen, npw, nlen);
    denc_explicit_bzero(opw, olen); free(opw);
    denc_explicit_bzero(npw, nlen); free(npw);
    return rc;
}

int main(int argc, char **argv) {
    if (argc < 2) { usage(); return 1; }
    int rc;
    if (strcmp(argv[1], "create") == 0)
        rc = cmd_create(argc - 2, argv + 2);
    else if (strcmp(argv[1], "open") == 0)
        rc = cmd_open(argc - 2, argv + 2);
    else if (strcmp(argv[1], "chpass") == 0)
        rc = cmd_chpass(argc - 2, argv + 2);
    else { usage(); return 1; }
    if (rc != DENC_OK) {
        fprintf(stderr, "denc: %s\n", denc_strerror(rc));
        return 2;
    }
    return 0;
}
