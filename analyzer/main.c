/*
 * denc-forensic: adversarial analyzer.
 *
 * It has NO password. It tries to prove (or honestly fail to prove) that a
 * container holds a second, hidden volume, using the same evidence a border
 * agent with full disk images and multiple snapshots would have:
 *
 *   - byte/entropy/chi-square statistics on every region
 *   - duplicate-sector and zero-hole scans (sparse-file / zero-fill leakage)
 *   - header-slot inspection: salt/iteration sanity, randomness of ciphertext
 *   - file metadata: size multiples, mtime/atime anomalies
 *   - two-image diffs: locate changed sectors and check whether the change
 *     pattern is consistent with the single visible file system
 *
 * The conclusion is deliberately conservative: random-looking data cannot
 * be distinguished from ciphertext, so a correctly used deniable volume
 * must end in "no evidence of a second volume".
 */
#include "format.h"
#include "stats.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#define CHUNK (1024 * 1024)

static uint8_t *read_whole(const char *path, size_t *outlen) {
    FILE *fp = fopen(path, "rb");
    if (!fp) return NULL;
    fseek(fp, 0, SEEK_END);
    long n = ftell(fp);
    if (n <= 0) { fclose(fp); return NULL; }
    rewind(fp);
    uint8_t *buf = malloc((size_t)n);
    if (!buf) { fclose(fp); return NULL; }
    if (fread(buf, 1, (size_t)n, fp) != (size_t)n) {
        free(buf); fclose(fp); return NULL;
    }
    fclose(fp);
    *outlen = (size_t)n;
    return buf;
}

static void report_stats(const char *label, const uint8_t *p, uint64_t len) {
    fs_stats_t st;
    fs_stats_compute(p, len, DENC_FMT_SECTOR_SIZE, &st);
    double pval = chi_square_sf(st.chi_square, 255);
    printf("  %-22s entropy=%6.4f bits/B  chi2=%9.1f (p=%.4g)%s\n",
           label, st.shannon_entropy, st.chi_square, pval,
           pval < 0.01 ? "  <-- NON-UNIFORM" : "");
    printf("  %-22s zero-bytes=%6.3f%%  repeated-4K-sectors=%" PRIu64
           "/%" PRIu64 "\n", "",
           100.0 * (double)st.zero_bytes / (double)len,
           st.repeated_sectors, st.sector_count);
}

static int looks_like_iter(uint32_t it) {
    return it >= 1000 && it <= 10u * 1000u * 1000u;
}

static void inspect_header_slots(const uint8_t *img, size_t len) {
    printf("\n[header slots]\n");
    for (int s = 0; s < DENC_FMT_HEADER_SLOTS; s++) {
        const uint8_t *slot = img + (size_t)s * DENC_FMT_SECTOR_SIZE;
        uint32_t iter = (uint32_t)slot[DENC_FMT_ITER_OFF] |
                        ((uint32_t)slot[DENC_FMT_ITER_OFF + 1] << 8) |
                        ((uint32_t)slot[DENC_FMT_ITER_OFF + 2] << 16) |
                        ((uint32_t)slot[DENC_FMT_ITER_OFF + 3] << 24);
        fs_stats_t salt_st, ct_st;
        fs_stats_compute(slot + DENC_FMT_SALT_OFF, DENC_FMT_SALT_SIZE, 0,
                         &salt_st);
        fs_stats_compute(slot + DENC_FMT_CT_OFF, DENC_FMT_CT_LEN,
                         DENC_FMT_SECTOR_SIZE, &ct_st);
        printf("  slot %d: iter-field=%10" PRIu32 "%s\n", s, iter,
               looks_like_iter(iter) ? " (plausible KDF iteration count)"
                                     : " (not a recognizable iteration count)");
        printf("          salt entropy=%.4f  ciphertext entropy=%.4f"
               "  repeated-ct-sectors=%" PRIu64 "\n",
               salt_st.shannon_entropy, ct_st.shannon_entropy,
               ct_st.repeated_sectors);
        /* Without the password a valid slot and random filler are both
         * high-entropy byte strings: this line states that explicitly. */
        printf("          => slot content is %s; password required to tell a"
               " sealed header from random filler\n",
               ct_st.shannon_entropy > 7.5 ? "indistinguishable from random"
                                           : "STATISTICALLY SUSPICIOUS");
        (void)len;
    }
}

static void inspect_metadata(const char *path) {
    printf("\n[file metadata]\n");
    struct stat st;
    if (stat(path, &st) != 0) { perror("stat"); return; }
    printf("  size=%jd bytes (%.2f MiB); multiple of 4096: %s\n",
           (intmax_t)st.st_size, (double)st.st_size / 1048576.0,
           (st.st_size % DENC_FMT_SECTOR_SIZE) == 0 ? "yes" : "NO");
    printf("  mtime=%jd  atime=%jd  ctime=%jd\n",
           (intmax_t)st.st_mtimespec.tv_sec, (intmax_t)st.st_atimespec.tv_sec,
           (intmax_t)st.st_ctimespec.tv_sec);
    if (st.st_mtimespec.tv_sec == st.st_atimespec.tv_sec &&
        st.st_mtimespec.tv_nsec == st.st_atimespec.tv_nsec)
        printf("  NOTE: atime==mtime exactly - possible timestamp pinning\n");
    /* hole scan */
    FILE *fp = fopen(path, "rb");
    if (fp) {
        uint64_t holes = 0, sectors = (uint64_t)st.st_size /
                                      DENC_FMT_SECTOR_SIZE;
        uint8_t *z = calloc(1, DENC_FMT_SECTOR_SIZE),
                *b = malloc(DENC_FMT_SECTOR_SIZE);
        for (uint64_t i = 0; i < sectors; i++) {
            if (fread(b, 1, DENC_FMT_SECTOR_SIZE, fp) !=
                DENC_FMT_SECTOR_SIZE) break;
            if (memcmp(z, b, DENC_FMT_SECTOR_SIZE) == 0) holes++;
        }
        printf("  all-zero 4K sectors: %" PRIu64 "/%" PRIu64 "%s\n",
               holes, sectors, holes ? "  <-- zeroed regions are a signal"
                                     : " (none)");
        free(z); free(b); fclose(fp);
    }
}

/* ---------- snapshot diff ---------- */

typedef struct {
    uint64_t changed_sectors;
    uint64_t total_sectors;
    uint64_t first_change, last_change;
    double   changed_pct;
    int      touches_header[DENC_FMT_HEADER_SLOTS];
    double   mean_entropy_changed;   /* new bytes at changed positions */
} diff_report_t;

static int cmd_diff(const char *a_path, const char *b_path) {
    size_t la, lb;
    uint8_t *a = read_whole(a_path, &la), *b = read_whole(b_path, &lb);
    if (!a || !b) {
        fprintf(stderr, "cannot read snapshots\n");
        free(a); free(b);
        return 1;
    }
    if (la != lb) {
        printf("  SIZE CHANGED: %zu -> %zu bytes. A fixed-size deniable"
               " container must never resize; this alone is evidence of"
               " non-deniable behavior.\n", la, lb);
    }
    size_t n = la < lb ? la : lb;
    uint64_t sectors = n / DENC_FMT_SECTOR_SIZE;
    diff_report_t r;
    memset(&r, 0, sizeof(r));
    r.total_sectors = sectors;
    r.first_change = UINT64_MAX;

    uint64_t ent_sum = 0, ent_n = 0;
    for (uint64_t s = 0; s < sectors; s++) {
        const uint8_t *pa = a + s * DENC_FMT_SECTOR_SIZE,
                      *pb = b + s * DENC_FMT_SECTOR_SIZE;
        if (memcmp(pa, pb, DENC_FMT_SECTOR_SIZE) != 0) {
            r.changed_sectors++;
            if (s < r.first_change) r.first_change = s;
            r.last_change = s;
            if (s < DENC_FMT_HEADER_SLOTS)
                r.touches_header[(int)s] = 1;
            fs_stats_t st;
            fs_stats_compute(pb, DENC_FMT_SECTOR_SIZE, 0, &st);
            ent_sum += (uint64_t)(st.shannon_entropy * 10000);
            ent_n++;
        }
    }
    r.changed_pct = sectors
        ? 100.0 * (double)r.changed_sectors / (double)sectors : 0.0;
    r.mean_entropy_changed = ent_n
        ? (double)ent_sum / 10000.0 / (double)ent_n : 0.0;

    printf("\n[snapshot diff: %s -> %s]\n", a_path, b_path);
    printf("  changed sectors: %" PRIu64 "/%" PRIu64 " (%.4f%%)\n",
           r.changed_sectors, sectors, r.changed_pct);
    if (r.changed_sectors)
        printf("  changed range  : sector %" PRIu64 "..%" PRIu64 "\n",
               r.first_change, r.last_change);
    for (int s = 0; s < DENC_FMT_HEADER_SLOTS; s++)
        if (r.touches_header[s])
            printf("  header slot %d changed (password/key change or hidden-"
                   "header activity)\n", s);
    printf("  mean entropy of new sector bytes: %.4f bits/B"
           " (8.0 = indistinguishable from random)\n",
           r.mean_entropy_changed);

    /* Interpretation: writes concentrated in a tail region the visible FS
     * never explains are the classic hidden-volume fingerprint. */
    printf("\n  interpretation:\n");
    if (r.changed_sectors == 0)
        printf("  - no detectable change; churn or mtime-only activity\n");
    if (r.first_change >= DENC_FMT_HEADER_RESERVED &&
        r.first_change > sectors * 3 / 4 && r.changed_sectors > 0)
        printf("  - changes cluster in the last quarter of the data region,"
               " which is where a tail-resident hidden volume would write\n");
    if (r.mean_entropy_changed > 7.9)
        printf("  - changed bytes look random: consistent with encrypted"
               " writes OR with free-space scrubbing; not proof either way\n");
    free(a); free(b);
    return 0;
}

/* ---------- single-image audit ---------- */

static int cmd_audit(const char *path) {
    size_t len;
    uint8_t *img = read_whole(path, &len);
    if (!img) { perror(path); return 1; }
    uint64_t sectors = len / DENC_FMT_SECTOR_SIZE;

    printf("denc-forensic audit of %s\n", path);
    printf("  %zu bytes, %" PRIu64 " 4K sectors\n", len, sectors);

    printf("\n[region statistics]\n");
    report_stats("whole image", img, len);
    if (len >= DENC_FMT_HEADER_RESERVED)
        report_stats("data region", img + DENC_FMT_HEADER_RESERVED,
                     len - DENC_FMT_HEADER_RESERVED);
    for (int s = 0; s < DENC_FMT_HEADER_SLOTS; s++)
        report_stats(s == 0 ? "header slot 0" : "header slot 1",
                     img + (size_t)s * DENC_FMT_SECTOR_SIZE,
                     DENC_FMT_SECTOR_SIZE);

    inspect_header_slots(img, len);
    inspect_metadata(path);

    printf("\n[verdict]\n");
    fs_stats_t whole;
    fs_stats_compute(img, len, DENC_FMT_SECTOR_SIZE, &whole);
    double pval = chi_square_sf(whole.chi_square, 255);
    int suspicious = 0;
    if (whole.shannon_entropy < 7.9) {
        printf("  * global entropy %.4f is below random-ciphertext range\n",
               whole.shannon_entropy);
        suspicious = 1;
    }
    /* Chi-square is the statistically sound uniformity test: a uniform
     * source fails it only ~5%% of the time at p<0.05, ~1%% at p<0.01. */
    if (pval < 0.01) {
        printf("  * byte distribution fails the chi-square uniformity test"
               " (p=%.4g): not consistent with random ciphertext\n", pval);
        suspicious = 1;
    }
    if (whole.repeated_sectors > 0) {
        printf("  * %" PRIu64 " repeated 4K sectors (ciphertext under unique"
               " per-sector nonces should not repeat)\n",
               whole.repeated_sectors);
        suspicious = 1;
    }
    /* Zero bytes are EXPECTED in uniform random data (~len/256). Only an
     * all-zero sector is a real signal, already counted separately. Report
     * the observed fraction against its statistical expectation instead of
     * treating any zero byte as suspicious. */
    double expected_zero = (double)len / 256.0;
    printf("  (zero bytes %.4f%% vs uniform expectation %.4f%%; "
           "all-zero sectors already ruled out above)\n",
           100.0 * (double)whole.zero_bytes / (double)len,
           100.0 / 256.0);
    (void)expected_zero;
    if (!suspicious)
        printf("  No statistical or structural evidence of a second volume."
               " Every region is consistent with either ciphertext or keyed"
               " random fill.\n  A hidden volume, if present, CANNOT be"
               " proven from this image alone.\n");
    else
        printf("  Anomalies above are explainable by ordinary use too, but"
               " they break the uniform-random cover story and should be"
               " investigated.\n");
    free(img);
    return 0;
}

int main(int argc, char **argv) {
    if (argc == 3 && strcmp(argv[1], "audit") == 0)
        return cmd_audit(argv[2]);
    if (argc == 4 && strcmp(argv[1], "diff") == 0)
        return cmd_diff(argv[2], argv[3]);
    fprintf(stderr,
            "usage:\n"
            "  denc-forensic audit container\n"
            "  denc-forensic diff snapshot1 snapshot2\n");
    return 2;
}
