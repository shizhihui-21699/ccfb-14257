#ifndef FORENSIC_STATS_H
#define FORENSIC_STATS_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    double   shannon_entropy;       /* bits/byte, max 8 */
    double   chi_square;            /* vs uniform 1/256 */
    double   chi_critical_p05;      /* df=255 critical ~293.25 */
    uint64_t zero_bytes;
    uint64_t total_bytes;
    uint64_t repeated_sectors;      /* sectors whose 4K content repeats */
    uint64_t sector_count;
    double   mean_byte;
} fs_stats_t;

void fs_stats_compute(const uint8_t *data, uint64_t len,
                      uint64_t sector_size, fs_stats_t *out);

/* Chi-square survival function (regularized upper gamma Q(1/2, x/2)).
 * Approximation via the standard incomplete-gamma series/continued fraction. */
double chi_square_sf(double chi2, int df);

#endif
