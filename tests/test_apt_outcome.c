/* pkgx_txn_classify: the post-effect truth table. The two cases codex called
 * out — fetch-before-effect (nothing applied) versus interrupted-dpkg-after-
 * effect (ran, left broken) — plus the rest. Pure; no libapt. ASan/UBSan. */
#include "../src/apt_status.h"

#include <stdio.h>

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
    /* entered, execution_began, committed_ok, broken */

    /* gate refused an OK plan: internal inconsistency, host untouched. */
    CHECK(pkgx_txn_classify(0, 0, 0, 0) == PKGX_APT_INTERNAL,
          "committer never entered -> INTERNAL");

    /* fetch/setup failed before dpkg ran: receipt spent, host unchanged. */
    CHECK(pkgx_txn_classify(1, 0, 0, 0) == PKGX_APT_NOT_APPLIED,
          "fetch-before-effect: entered but no execution -> NOT_APPLIED");
    /* a stale `broken` flag must not be trusted before execution began. */
    CHECK(pkgx_txn_classify(1, 0, 0, 1) == PKGX_APT_NOT_APPLIED,
          "no execution: broken flag is ignored -> NOT_APPLIED");

    /* dpkg ran to completion, db consistent. */
    CHECK(pkgx_txn_classify(1, 1, 1, 0) == PKGX_APT_OK,
          "dpkg completed, not broken -> OK");

    /* dpkg ran but left the db broken (interrupted / partial). */
    CHECK(pkgx_txn_classify(1, 1, 0, 1) == PKGX_APT_BROKEN,
          "interrupted-dpkg-after-effect: ran, left broken -> BROKEN");
    /* even a 'completed' result is BROKEN if ground truth says so. */
    CHECK(pkgx_txn_classify(1, 1, 1, 1) == PKGX_APT_BROKEN,
          "dpkg 'completed' but ground truth broken -> BROKEN");

    /* dpkg failed but unwound cleanly: consistent db, distinct from broken. */
    CHECK(pkgx_txn_classify(1, 1, 0, 0) == PKGX_APT_COMMIT_FAILED,
          "dpkg failed, db consistent -> COMMIT_FAILED");

    printf("%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
