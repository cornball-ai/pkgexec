/* pkgx_spawn_wait: exit status, complete-payload delivery, and early-close
 * failure without a SIGPIPE killing this process. No shell, no libapt. The
 * parent does NOT mask SIGPIPE, so if the helper failed to guard the write the
 * early-close case would crash this test rather than fail a check. ASan/UBSan. */
#include "../src/spawn.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
    int started;

    /* no input: exit status is the whole result; the child ran (started=1). */
    const char *t[] = {"/bin/true", NULL};
    started = -1;
    CHECK(pkgx_spawn_wait(t, NULL, &started) == 0, "true with no input -> 0");
    CHECK(started == 1, "true: child started");

    /* dpkg-ran-and-failed shape: the child started even though it exits non-zero.
     * This is exactly the effect_issued=true case for the shelled mechanisms —
     * the host may have been mutated, so `started` must not collapse with 'ok'. */
    const char *f[] = {"/bin/false", NULL};
    started = -1;
    CHECK(pkgx_spawn_wait(f, NULL, &started) != 0, "false with no input -> non-zero");
    CHECK(started == 1, "false: child started (effect issued despite failure)");

    const char *missing[] = {"/nonexistent/pkgx-abcxyz", NULL};
    CHECK(pkgx_spawn_wait(missing, NULL, NULL) != 0,
          "missing binary -> non-zero (NULL started tolerated)");

    /* NULL argv: nothing is spawned, so started must read 0, not a stale value. */
    started = -1;
    CHECK(pkgx_spawn_wait(NULL, NULL, &started) != 0, "NULL argv -> non-zero");
    CHECK(started == 0, "NULL argv: no child started");

    /* a child that consumes all of stdin and exits 0: full delivery. dd to
     * /dev/null reads its input and writes nothing to our stdout. */
    const char *sink[] = {"/usr/bin/dd", "of=/dev/null", "status=none", NULL};
    char payload[4096];
    memset(payload, 'x', sizeof payload - 1);
    payload[sizeof payload - 1] = '\0';
    started = -1;
    CHECK(pkgx_spawn_wait(sink, payload, &started) == 0,
          "child consumes the full payload and exits 0 -> 0");
    CHECK(started == 1, "dd sink: child started");

    /* a child that never reads stdin and exits immediately: a large payload
     * cannot be delivered (the read end closes), so this fails — and the SIGPIPE
     * that a naive write() would raise must NOT kill this process. The child did
     * start, so started=1 even though delivery failed. */
    size_t big_len = 256 * 1024;
    char *big = malloc(big_len + 1);
    CHECK(big != NULL, "allocate the large payload");
    if (big != NULL) {
        memset(big, 'y', big_len);
        big[big_len] = '\0';
        started = -1;
        CHECK(pkgx_spawn_wait(t, big, &started) != 0,
              "child closes stdin early -> non-zero, process survived");
        CHECK(started == 1, "early-close: child started even though delivery failed");
        free(big);
    }

    /* --- child-only extra environment: the hold/configure committers give the
     * spawned dpkg DPKG_FRONTEND_LOCKED=true so it skips the frontend lock the
     * effector holds, WITHOUT leaking that flag into this process's environment.
     * Establish a clean baseline first so the no-leak assertion is robust. --- */
    unsetenv("DPKG_FRONTEND_LOCKED");

    const char *env_locked[] = {"DPKG_FRONTEND_LOCKED=true", NULL};
    /* /bin/sh is argv[0] (absolute); the child exits 0 iff it sees the flag set. */
    const char *see_it[] = {"/bin/sh", "-c",
                            "test \"$DPKG_FRONTEND_LOCKED\" = true", NULL};
    started = -1;
    CHECK(pkgx_spawn_wait_env(see_it, NULL, env_locked, &started) == 0,
          "spawn_wait_env: child sees DPKG_FRONTEND_LOCKED=true");
    CHECK(started == 1, "spawn_wait_env: frontend-locked child started");

    /* No ambient leak: the flag was given to the child only, so this process's
     * environment is untouched. */
    CHECK(getenv("DPKG_FRONTEND_LOCKED") == NULL,
          "spawn_wait_env: parent environment not polluted (child-only)");

    /* A child spawned WITHOUT the extra env must NOT see the flag — both through the
     * plain pkgx_spawn_wait and through pkgx_spawn_wait_env with a NULL extra list. */
    const char *unset[] = {"/bin/sh", "-c", "test -z \"$DPKG_FRONTEND_LOCKED\"", NULL};
    started = -1;
    CHECK(pkgx_spawn_wait(unset, NULL, &started) == 0,
          "plain spawn: child does NOT see DPKG_FRONTEND_LOCKED");
    started = -1;
    CHECK(pkgx_spawn_wait_env(unset, NULL, NULL, &started) == 0,
          "spawn_wait_env NULL extra: child does NOT see DPKG_FRONTEND_LOCKED");

    printf("%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
