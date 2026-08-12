/* Exec-child isolation: after applying the hygiene primitives, a child reached
 * through fork+exec must see none of the parent's secret (the receipt token, an
 * inherited APT_CONFIG) and none of its inherited non-standard fds. This is the
 * property finding-5 asks for, proven across a real exec (where FD_CLOEXEC
 * actually takes effect). Built with ASan/UBSan (see Makefile). */
#include "../src/harden.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

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

int main(void) {
    /* fd 3 = an open, inheritable /dev/null the child must NOT see. */
    int nul = open("/dev/null", O_RDWR);
    if (nul < 0) {
        fprintf(stderr, "open /dev/null failed\n");
        return 2;
    }
    if (nul != 3) {
        if (dup2(nul, 3) < 0) {
            return 2;
        }
        close(nul);
    }

    /* A secret in the environment, standing in for the receipt token, plus a
     * dangerous inherited config var. */
    setenv("SNEAKY", "1b9d6bcd1e7f4a3bd2c5e8f0a4d7c9e2", 1);
    setenv("APT_CONFIG", "/evil.conf", 1);

    CHECK(pkgx_cloexec_from(3) == 0, "cloexec_from(3)");
    CHECK(pkgx_scrub_env() == 0, "scrub_env");
    CHECK(pkgx_null_stdin() == 0, "null_stdin");

    /* Child exits 0 only if the secret env is gone, APT_CONFIG is gone, and the
     * inherited fd 3 is closed (writing to it must fail). */
    const char *script =
        "status=0\n"
        "[ -n \"$SNEAKY\" ] && status=1\n"
        "[ -n \"$APT_CONFIG\" ] && status=1\n"
        "[ -e /proc/self/fd/3 ] && status=1\n" /* fd 3 still open => a leak */
        "exit $status\n";

    pid_t pid = fork();
    if (pid < 0) {
        CHECK(0, "fork");
    } else if (pid == 0) {
        execl("/bin/sh", "sh", "-c", script, (char *) NULL);
        _exit(127);
    } else {
        int st = 0;
        waitpid(pid, &st, 0);
        CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0,
              "exec'd child sees no receipt/env leak and no inherited fd");
    }

    printf("%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
