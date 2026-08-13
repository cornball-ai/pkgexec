/* See transport.h. One request per connection (the broker's model): connect,
 * authenticate the peer, send one frame, read one frame, close. */
#include "transport.h"

#include <errno.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

/* Absolute CLOCK_MONOTONIC instant `ms` from now. -1 on clock failure. */
static int deadline_at(struct timespec *dl, int ms) {
    if (clock_gettime(CLOCK_MONOTONIC, dl) != 0) {
        return -1;
    }
    dl->tv_sec += ms / 1000;
    long ns = dl->tv_nsec + (long) (ms % 1000) * 1000000L;
    dl->tv_sec += ns / 1000000000L;
    dl->tv_nsec = ns % 1000000000L;
    return 0;
}

/* Milliseconds remaining until `dl`; <= 0 when past. A clock failure reads as
 * expired (fail closed). */
static long long ms_left(const struct timespec *dl) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        return 0;
    }
    return (long long) (dl->tv_sec - now.tv_sec) * 1000LL +
           (long long) (dl->tv_nsec - now.tv_nsec) / 1000000LL;
}

/* Wait for `events` on the nonblocking fd until the absolute deadline.
 * 0 = ready, -2 = deadline passed, -1 = poll error. */
static int wait_fd(int fd, short events, const struct timespec *dl) {
    for (;;) {
        long long left = ms_left(dl);
        if (left <= 0) {
            return -2;
        }
        struct pollfd p;
        p.fd = fd;
        p.events = events;
        p.revents = 0;
        int r = poll(&p, 1, (left > 60000) ? 60000 : (int) left);
        if (r < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (r == 0) {
            continue; /* recheck the absolute deadline */
        }
        return 0; /* ready (or error-pending: the next read/write reports it) */
    }
}

/* Write exactly n bytes before the deadline. 0 ok, -1 error, -2 timeout. */
static int write_full(int fd, const void *buf, size_t n,
                      const struct timespec *dl) {
    const unsigned char *p = buf;
    size_t sent = 0;
    while (sent < n) {
        ssize_t w = write(fd, p + sent, n - sent);
        if (w < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                int wr = wait_fd(fd, POLLOUT, dl);
                if (wr != 0) {
                    return wr;
                }
                continue;
            }
            return -1;
        }
        sent += (size_t) w;
    }
    return 0;
}

/* Read exactly n bytes before the deadline. 0 ok, 1 EOF, -1 error, -2 timeout. */
static int read_full(int fd, void *buf, size_t n, const struct timespec *dl) {
    unsigned char *p = buf;
    size_t got = 0;
    while (got < n) {
        ssize_t r = read(fd, p + got, n - got);
        if (r < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                int wr = wait_fd(fd, POLLIN, dl);
                if (wr != 0) {
                    return wr;
                }
                continue;
            }
            return -1;
        }
        if (r == 0) {
            return 1;
        }
        got += (size_t) r;
    }
    return 0;
}

/* Connect (nonblocking, CLOEXEC) to the AF_UNIX path before the deadline.
 * Returns the fd, or -1 with *err set. EAGAIN (listener backlog full) retries
 * on a fresh socket within the deadline; everything else fails immediately. */
static int connect_deadline(const char *path, const struct timespec *dl,
                            const char **err) {
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof addr);
    addr.sun_family = AF_UNIX;
    if (path == NULL || path[0] == '\0' ||
        strlen(path) >= sizeof addr.sun_path) {
        *err = "socket_path";
        return -1;
    }
    snprintf(addr.sun_path, sizeof addr.sun_path, "%s", path);
    for (;;) {
        int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
        if (fd < 0) {
            *err = "socket";
            return -1;
        }
        if (connect(fd, (struct sockaddr *) &addr, sizeof addr) == 0) {
            return fd;
        }
        if (errno == EINTR || errno == EINPROGRESS) {
            /* completion is signalled by POLLOUT; the result is SO_ERROR */
            if (wait_fd(fd, POLLOUT, dl) == 0) {
                int soerr = 0;
                socklen_t sl = sizeof soerr;
                if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &sl) == 0 &&
                    soerr == 0) {
                    return fd;
                }
            }
            close(fd);
            *err = "connect";
            return -1;
        }
        if (errno == EAGAIN) {
            close(fd);
            if (ms_left(dl) <= 0) {
                *err = "deadline";
                return -1;
            }
            struct timespec nap = {0, 20L * 1000000L};
            nanosleep(&nap, NULL);
            continue;
        }
        close(fd);
        *err = "connect";
        return -1;
    }
}

int pkgx_transport_tx(void *ctx, const char *req, size_t reqlen, char **resp,
                      size_t *resplen) {
    pkgx_transport *t = ctx;
    t->err = NULL;
    *resp = NULL;
    *resplen = 0;
    if (req == NULL || reqlen == 0 || reqlen > PKGX_FRAME_MAX_BODY) {
        t->err = "request_size";
        return -1;
    }
    struct timespec dl;
    int ms = (t->timeout_ms > 0) ? t->timeout_ms : PKGX_TRANSPORT_TIMEOUT_MS;
    if (deadline_at(&dl, ms) != 0) {
        t->err = "clock";
        return -1;
    }

    int fd = connect_deadline(t->socket_path, &dl, &t->err);
    if (fd < 0) {
        return -1;
    }

    /* Authenticate the peer BEFORE any byte leaves the process. SO_PEERCRED is
     * the kernel-verified identity of whoever bound/listens on the socket; the
     * receipt token in `req` is never written to any other uid. */
    struct ucred cr;
    socklen_t cl = sizeof cr;
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cr, &cl) != 0 ||
        cl != sizeof cr) {
        close(fd);
        t->err = "peer";
        return -1;
    }
    if (cr.uid != t->required_peer_uid) {
        close(fd);
        t->err = "peer_uid";
        return -1;
    }

    unsigned char hdr[5];
    hdr[0] = (unsigned char) PKGX_FRAME_VERSION;
    hdr[1] = (unsigned char) ((reqlen >> 24) & 0xff);
    hdr[2] = (unsigned char) ((reqlen >> 16) & 0xff);
    hdr[3] = (unsigned char) ((reqlen >> 8) & 0xff);
    hdr[4] = (unsigned char) (reqlen & 0xff);
    int wr = write_full(fd, hdr, sizeof hdr, &dl);
    if (wr == 0) {
        wr = write_full(fd, req, reqlen, &dl);
    }
    if (wr != 0) {
        close(fd);
        t->err = (wr == -2) ? "deadline" : "send";
        return -1;
    }

    unsigned char rhdr[5];
    int rr = read_full(fd, rhdr, sizeof rhdr, &dl);
    if (rr != 0) {
        close(fd);
        t->err = (rr == 1) ? "frame_eof" : (rr == -2) ? "deadline" : "recv";
        return -1;
    }
    if (rhdr[0] != (unsigned char) PKGX_FRAME_VERSION) {
        close(fd);
        t->err = "frame_version";
        return -1;
    }
    uint32_t rlen = ((uint32_t) rhdr[1] << 24) | ((uint32_t) rhdr[2] << 16) |
                    ((uint32_t) rhdr[3] << 8) | (uint32_t) rhdr[4];
    if (rlen > PKGX_FRAME_MAX_BODY) {
        close(fd);
        t->err = "frame_toolarge";
        return -1;
    }
    char *body = malloc((size_t) rlen + 1);
    if (body == NULL) {
        close(fd);
        t->err = "oom";
        return -1;
    }
    rr = read_full(fd, body, rlen, &dl);
    if (rr != 0) {
        free(body);
        close(fd);
        t->err = (rr == 1) ? "frame_eof" : (rr == -2) ? "deadline" : "recv";
        return -1;
    }
    body[rlen] = '\0';
    close(fd);
    *resp = body;
    *resplen = rlen;
    return 0;
}
