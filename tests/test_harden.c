/* Environment allowlist, inherited-fd closure, PKEXEC_UID read, and stdin
 * nulling. Built with ASan/UBSan (see Makefile). */
#include "../src/harden.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern char **environ;

static int checks = 0;
static int failures = 0;

#define CHECK(cond, msg)                                                     \
    do {                                                                    \
        checks++;                                                           \
        if (!(cond)) {                                                      \
            failures++;                                                     \
            fprintf(stderr, "FAIL: %s (%s:%d)\n", msg, __FILE__, __LINE__); \
        }                                                                  \
    } while (0)

static const char *SECRET = "1b9d6bcd1e7f4a3bd2c5e8f0a4d7c9e2";

int main(void) {
    uid_t uid = 0;

    /* --- PKEXEC_UID (before scrub, which erases it) --- */
    setenv("PKEXEC_UID", "1000", 1);
    CHECK(pkgx_read_pkexec_uid(&uid) == 0 && uid == 1000, "PKEXEC_UID read");
    setenv("PKEXEC_UID", "abc", 1);
    CHECK(pkgx_read_pkexec_uid(&uid) == -1, "non-numeric PKEXEC_UID refused");
    setenv("PKEXEC_UID", "99999999999999999999", 1);
    CHECK(pkgx_read_pkexec_uid(&uid) == -1, "out-of-range PKEXEC_UID refused");
    unsetenv("PKEXEC_UID");
    CHECK(pkgx_read_pkexec_uid(&uid) == -1, "absent PKEXEC_UID refused");

    /* --- inherited-fd cloexec --- */
    int fd = open("/dev/null", O_RDONLY); /* deliberately no O_CLOEXEC */
    CHECK(fd >= 3, "opened a test fd");
    CHECK((fcntl(fd, F_GETFD) & FD_CLOEXEC) == 0, "test fd starts non-cloexec");
    CHECK(pkgx_cloexec_from(3) == 0, "cloexec_from ok");
    CHECK((fcntl(fd, F_GETFD) & FD_CLOEXEC) != 0, "test fd now cloexec");
    close(fd);

    /* --- null stdin --- */
    CHECK(pkgx_null_stdin() == 0, "null_stdin ok");
    char c;
    CHECK(read(STDIN_FILENO, &c, 1) == 0, "stdin now reads EOF (/dev/null)");
    CHECK((fcntl(STDIN_FILENO, F_GETFD) & FD_CLOEXEC) == 0,
          "stdin stays inheritable across exec (not cloexec)");

    /* --- env scrub: allowlist only, secrets gone --- */
    setenv("APT_CONFIG", "/evil.conf", 1);
    setenv("LD_PRELOAD", "/evil.so", 1);
    setenv("SNEAKY", SECRET, 1);
    CHECK(pkgx_scrub_env() == 0, "scrub_env ok");
    CHECK(getenv("APT_CONFIG") == NULL, "APT_CONFIG dropped");
    CHECK(getenv("LD_PRELOAD") == NULL, "LD_PRELOAD dropped");
    CHECK(getenv("SNEAKY") == NULL, "inherited secret dropped");
    CHECK(getenv("PATH") != NULL &&
              strcmp(getenv("PATH"), "/usr/sbin:/usr/bin:/sbin:/bin") == 0,
          "PATH set to the allowlist value");
    CHECK(getenv("LC_ALL") != NULL && strcmp(getenv("LC_ALL"), "C") == 0,
          "LC_ALL=C");
    CHECK(getenv("DEBIAN_FRONTEND") != NULL &&
              strcmp(getenv("DEBIAN_FRONTEND"), "noninteractive") == 0,
          "DEBIAN_FRONTEND=noninteractive");
    int leaked = 0;
    for (char **e = environ; *e; e++) {
        if (strstr(*e, SECRET) != NULL) {
            leaked = 1;
        }
    }
    CHECK(!leaked, "no environment entry carries the secret after scrub");

    printf("%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
