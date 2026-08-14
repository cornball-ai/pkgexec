/* See result.h. */
#include "result.h"

#include <errno.h>
#include <fcntl.h>
#include <jansson.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>

const char *pkgx_status_name(pkgx_apt_status st) {
    switch (st) {
    case PKGX_APT_OK:
        return "ok";
    case PKGX_APT_NO_OP:
        return "no_op";
    case PKGX_APT_LOCKED:
        return "apt_locked";
    case PKGX_APT_NOT_OWNED:
        return "package_not_owned";
    case PKGX_APT_HELD:
        return "held";
    case PKGX_APT_PROTECTED:
        return "protected_package";
    case PKGX_APT_NO_INTENT:
        return "no_intent";
    case PKGX_APT_RESOLVE_FAILED:
        return "resolve_failed";
    case PKGX_APT_NOT_APPLIED:
        return "not_applied";
    case PKGX_APT_COMMIT_FAILED:
        return "operation_failed";
    case PKGX_APT_BROKEN:
        return "dpkg_broken";
    case PKGX_APT_INTERNAL:
        return "internal";
    }
    return "internal"; /* unreachable: the switch is total */
}

int pkgx_result_json(pkgx_apt_status st, int effect_issued,
                     const char *correlation_id, const char *detail, char *out,
                     size_t outlen) {
    if (out == NULL || outlen == 0) {
        return -1;
    }
    json_t *o = json_object();
    if (o == NULL) {
        return -1;
    }
    /* Insertion order is preserved by Jansson, so the object is deterministic.
     * json_string returns NULL on non-UTF-8, and json_object_set_new rejects a
     * NULL value with -1 — so a bad field fails closed rather than emitting a
     * malformed record. */
    int bad = 0;
    bad |= json_object_set_new(o, "status", json_string(pkgx_status_name(st)));
    bad |= json_object_set_new(o, "effect_issued", json_boolean(effect_issued != 0));
    bad |= json_object_set_new(o, "correlation_id",
                               json_string(correlation_id ? correlation_id : ""));
    bad |= json_object_set_new(o, "detail", json_string(detail ? detail : ""));
    if (bad != 0) {
        json_decref(o);
        return -1;
    }
    char *s = json_dumps(o, JSON_COMPACT);
    json_decref(o);
    if (s == NULL) {
        return -1;
    }
    size_t n = strlen(s);
    if (n + 1 > outlen) {
        free(s);
        return -1; /* buffer too small: out is untouched */
    }
    memcpy(out, s, n + 1);
    free(s);
    return (int) n;
}

int pkgx_result_emit(int fd, pkgx_apt_status st, int effect_issued,
                     const char *correlation_id, const char *detail) {
    char buf[512];
    int n = pkgx_result_json(st, effect_issued, correlation_id, detail, buf,
                             sizeof buf);
    if (n < 0) {
        return -1;
    }
    buf[n] = '\n'; /* pkgx_result_json wrote n bytes + NUL, and n < sizeof buf */
    size_t total = (size_t) n + 1;

    /* Ignore SIGPIPE for the write so a result pipe the caller already closed
     * yields EPIPE (which we detect) instead of killing this process — a closed
     * result channel must be a reported failure, not a signal death that could
     * look like a clean exit. */
    struct sigaction ign, old;
    memset(&ign, 0, sizeof ign);
    ign.sa_handler = SIG_IGN;
    sigemptyset(&ign.sa_mask);
    if (sigaction(SIGPIPE, &ign, &old) != 0) {
        return -1; /* fail closed: cannot guarantee the write is observable */
    }
    int rc = 0;
    size_t off = 0;
    while (off < total) {
        ssize_t w = write(fd, buf + off, total - off);
        if (w < 0) {
            if (errno == EINTR) {
                continue;
            }
            rc = -1; /* EPIPE (closed pipe) or other I/O error */
            break;
        }
        if (w == 0) {
            rc = -1;
            break;
        }
        off += (size_t) w;
    }
    if (sigaction(SIGPIPE, &old, NULL) != 0) {
        rc = -1; /* restoration failed: report so the caller does not trust it */
    }
    return rc;
}

int pkgx_result_channel_open(void) {
    /* Save the caller's stdout as the dedicated, close-on-exec result fd. */
    int rfd = dup(STDOUT_FILENO);
    if (rfd < 0) {
        return -1;
    }
    if (fcntl(rfd, F_SETFD, FD_CLOEXEC) != 0) {
        close(rfd);
        return -1;
    }
    /* Point fd 1 at stderr: effector / libapt / spawned-dpkg output on stdout now
     * lands on stderr, never in the result channel. Never restored. */
    if (dup2(STDERR_FILENO, STDOUT_FILENO) < 0) {
        close(rfd);
        return -1;
    }
    return rfd;
}
