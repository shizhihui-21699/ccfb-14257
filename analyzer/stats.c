#include "stats.h"
#include <math.h>
#include <string.h>
#include <stdlib.h>

/* ---- incomplete gamma for the chi-square p-value ---- */

static double gammln(double x) {
    double cof[6] = {76.18009172947146, -86.50532032941677, 24.01409824083091,
                     -1.231739572450155, 0.1208650973866179e-2,
                     -0.5395239384953e-5};
    double y = x, tmp = x + 5.5;
    tmp -= (x + 0.5) * log(tmp);
    double ser = 1.000000000190015;
    for (int j = 0; j < 6; j++) ser += cof[j] / ++y;
    return -tmp + log(2.5066282746310005 * ser / x);
}

static double gser(double a, double x) {       /* P(a,x) series */
    double ap = a, sum = 1.0 / a, del = sum;
    for (int n = 0; n < 200; n++) {
        ap += 1.0;
        del *= x / ap;
        sum += del;
        if (fabs(del) < fabs(sum) * 1e-14) break;
    }
    return sum * exp(-x + a * log(x) - gammln(a));
}

static double gcf(double a, double x) {        /* Q(a,x) continued fraction */
    double b = x + 1.0 - a, c = 1e300, d = 1.0 / b, h = d;
    for (int n = 1; n < 200; n++) {
        double an = -(double)n * ((double)n - a);
        b += 2.0;
        double an_d = an * d + b;
        if (fabs(an_d) < 1e-300) an_d = 1e-300;
        d = 1.0 / an_d;
        double an_c = b + an / c;
        if (fabs(an_c) < 1e-300) an_c = 1e-300;
        c = an_c;
        double del = d * c;
        h *= del;
        if (fabs(del - 1.0) < 1e-14) break;
    }
    return exp(-x + a * log(x) - gammln(a)) * h;
}

double chi_square_sf(double chi2, int df) {
    if (chi2 < 0) return 1.0;
    double a = df / 2.0, x = chi2 / 2.0;
    if (x < a + 1.0) return 1.0 - gser(a, x);
    return gcf(a, x);
}

/* FNV-1a 64-bit for duplicate-sector detection. */
static uint64_t fnv1a(const uint8_t *p, size_t n) {
    uint64_t h = 1469598103934665603ULL;
    for (size_t i = 0; i < n; i++) { h ^= p[i]; h *= 1099511628211ULL; }
    return h;
}

static int u64cmp(const void *a, const void *b) {
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}

void fs_stats_compute(const uint8_t *data, uint64_t len,
                      uint64_t sector_size, fs_stats_t *out) {
    memset(out, 0, sizeof(*out));
    out->total_bytes = len;
    out->chi_critical_p05 = 293.25;
    if (len == 0) return;

    uint64_t hist[256] = {0};
    double acc = 0.0;
    for (uint64_t i = 0; i < len; i++) {
        hist[data[i]]++;
        acc += data[i];
        if (data[i] == 0) out->zero_bytes++;
    }
    out->mean_byte = acc / (double)len;

    double ent = 0.0, expected = (double)len / 256.0, chi = 0.0;
    for (int b = 0; b < 256; b++) {
        if (hist[b]) {
            double p = (double)hist[b] / (double)len;
            ent -= p * (log(p) / log(2.0));
        }
        double d = (double)hist[b] - expected;
        chi += d * d / expected;
    }
    out->shannon_entropy = ent;
    out->chi_square = chi;

    /* duplicate sectors */
    if (sector_size > 0 && len >= sector_size) {
        uint64_t n = len / sector_size;
        out->sector_count = n;
        uint64_t *hashes = malloc(n * sizeof(uint64_t));
        if (hashes) {
            for (uint64_t i = 0; i < n; i++)
                hashes[i] = fnv1a(data + i * sector_size,
                                  (size_t)sector_size);
            qsort(hashes, n, sizeof(uint64_t), u64cmp);
            uint64_t rep = 0;
            for (uint64_t i = 1; i < n; i++)
                if (hashes[i] == hashes[i - 1]) rep++;
            out->repeated_sectors = rep;
            free(hashes);
        }
    }
}
