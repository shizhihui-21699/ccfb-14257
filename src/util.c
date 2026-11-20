#include "common.h"

void denc_explicit_bzero(void *p, size_t n) {
#if defined(__STDC_LIB_EXT1__)
    memset_s(p, n, 0, n);
#else
    /* Volatile store loop: standard C the compiler is not allowed to elide. */
    volatile unsigned char *vp = (volatile unsigned char *)p;
    while (n--) *vp++ = 0;
#endif
}

const char *denc_strerror(int rc) {
    switch (rc) {
    case DENC_OK:          return "ok";
    case DENC_ERR_USAGE:   return "usage error";
    case DENC_ERR_IO:      return "i/o error";
    case DENC_ERR_CRYPTO:  return "crypto error";
    case DENC_ERR_FORMAT:  return "bad password or corrupt container";
    case DENC_ERR_NOSPACE: return "no space left";
    case DENC_ERR_NOENT:   return "no such file";
    case DENC_ERR_EXISTS:  return "file already exists";
    case DENC_ERR_DENIED:  return "write blocked (hidden region protection)";
    default:               return "unknown error";
    }
}
