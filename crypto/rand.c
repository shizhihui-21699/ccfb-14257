#include "rand.h"
#include "common.h"

#if defined(__APPLE__)
#include <stdlib.h>
#elif defined(__unix__)
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#endif

int denc_random(uint8_t *buf, size_t len) {
#if defined(__APPLE__)
    arc4random_buf(buf, len);
    return DENC_OK;
#else
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return DENC_ERR_CRYPTO;
    size_t done = 0;
    while (done < len) {
        ssize_t n = read(fd, buf + done, len - done);
        if (n < 0) {
            if (errno == EINTR) continue;
            close(fd);
            return DENC_ERR_CRYPTO;
        }
        if (n == 0) { close(fd); return DENC_ERR_CRYPTO; }
        done += (size_t)n;
    }
    close(fd);
    return DENC_OK;
#endif
}
