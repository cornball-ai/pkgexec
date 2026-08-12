/* Process hygiene primitives. See harden.h. */
#include "harden.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

int pkgx_read_pkexec_uid(uid_t *uid) {
    const char *s = getenv("PKEXEC_UID");
    if (s == NULL || *s == '\0') {
        return -1;
    }
    for (const char *p = s; *p; p++) {
        if (*p < '0' || *p > '9') {
            return -1;
        }
    }
    errno = 0;
    char *end = NULL;
    unsigned long long v = strtoull(s, &end, 10);
    if (errno != 0 || end == s || *end != '\0') { /* errno catches overflow */
        return -1;
    }
    uid_t u = (uid_t) v;
    if ((unsigned long long) u != v) { /* did not fit uid_t */
        return -1;
    }
    *uid = u;
    return 0;
}

int pkgx_scrub_env(void) {
    if (clearenv() != 0) {
        return -1;
    }
    if (setenv("PATH", "/usr/sbin:/usr/bin:/sbin:/bin", 1) != 0 ||
        setenv("LC_ALL", "C", 1) != 0 ||
        setenv("DEBIAN_FRONTEND", "noninteractive", 1) != 0) {
        return -1;
    }
    return 0;
}

int pkgx_cloexec_from(int lowest) {
    DIR *d = opendir("/proc/self/fd");
    if (d == NULL) {
        return -1;
    }
    int dirfd_no = dirfd(d);
    struct dirent *e;
    int rc = 0;
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] < '0' || e->d_name[0] > '9') {
            continue;
        }
        int fd = (int) strtol(e->d_name, NULL, 10);
        if (fd < lowest || fd == dirfd_no) {
            continue;
        }
        int flags = fcntl(fd, F_GETFD);
        if (flags < 0) {
            continue; /* raced closed */
        }
        if (!(flags & FD_CLOEXEC) && fcntl(fd, F_SETFD, flags | FD_CLOEXEC) < 0) {
            rc = -1;
        }
    }
    closedir(d);
    return rc;
}

int pkgx_null_stdin(void) {
    /* Opened WITHOUT O_CLOEXEC: stdin must stay open across a child's exec (as
     * /dev/null), not close on it. */
    int fd = open("/dev/null", O_RDONLY);
    if (fd < 0) {
        return -1;
    }
    if (fd != STDIN_FILENO) {
        if (dup2(fd, STDIN_FILENO) < 0) {
            close(fd);
            return -1;
        }
        close(fd);
    }
    /* Guarantee fd 0 is inheritable even when open() returned fd 0 directly
     * (stdin had been closed), where dup2 never ran to clear a cloexec bit. */
    int flags = fcntl(STDIN_FILENO, F_GETFD);
    if (flags < 0) {
        return -1;
    }
    if ((flags & FD_CLOEXEC) &&
        fcntl(STDIN_FILENO, F_SETFD, flags & ~FD_CLOEXEC) < 0) {
        return -1;
    }
    return 0;
}
