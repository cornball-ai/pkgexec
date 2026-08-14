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

    /* --- update (B): entered, refresh_ok, indexes_readable. Its own ground
     * truth — no dpkg, so it can never be BROKEN. --- */

    /* gate refused an OK plan: internal, nothing refreshed. */
    CHECK(pkgx_update_classify(0, 0, 0) == PKGX_APT_INTERNAL,
          "update: committer never entered -> INTERNAL");
    /* a stale refresh/readable flag must not be trusted if the gate refused. */
    CHECK(pkgx_update_classify(0, 1, 1) == PKGX_APT_INTERNAL,
          "update: not entered, flags ignored -> INTERNAL");
    /* refreshed and the new indexes read back. */
    CHECK(pkgx_update_classify(1, 1, 1) == PKGX_APT_OK,
          "update: refreshed + readable -> OK");
    /* ListUpdate failed: previous indexes stand, operation did not complete. */
    CHECK(pkgx_update_classify(1, 0, 1) == PKGX_APT_COMMIT_FAILED,
          "update: refresh failed -> COMMIT_FAILED");
    /* refreshed but the rebuilt indexes will not open: not a success. */
    CHECK(pkgx_update_classify(1, 1, 0) == PKGX_APT_COMMIT_FAILED,
          "update: refreshed but indexes unreadable -> COMMIT_FAILED");
    CHECK(pkgx_update_classify(1, 0, 0) == PKGX_APT_COMMIT_FAILED,
          "update: refresh failed and unreadable -> COMMIT_FAILED");

    /* --- hold/unhold (C): entered, selection_applied, selection_matches. Its own
     * ground truth — a selection write runs no scripts, so never BROKEN. --- */

    /* gate refused an OK plan: internal, no selection written. */
    CHECK(pkgx_hold_classify(0, 0, 0) == PKGX_APT_INTERNAL,
          "hold: committer never entered -> INTERNAL");
    CHECK(pkgx_hold_classify(0, 1, 1) == PKGX_APT_INTERNAL,
          "hold: not entered, flags ignored -> INTERNAL");
    /* set-selections succeeded and the read-back confirms the intended state. */
    CHECK(pkgx_hold_classify(1, 1, 1) == PKGX_APT_OK,
          "hold: applied + read-back matches -> OK");
    /* set-selections failed: prior selections intact, operation did not complete. */
    CHECK(pkgx_hold_classify(1, 0, 1) == PKGX_APT_COMMIT_FAILED,
          "hold: set-selections failed -> COMMIT_FAILED");
    /* applied but the read-back disagrees: not a trustworthy success. */
    CHECK(pkgx_hold_classify(1, 1, 0) == PKGX_APT_COMMIT_FAILED,
          "hold: applied but read-back mismatch -> COMMIT_FAILED");
    CHECK(pkgx_hold_classify(1, 0, 0) == PKGX_APT_COMMIT_FAILED,
          "hold: failed and mismatched -> COMMIT_FAILED");

    /* --- transaction inner-lock hand-off (A): unlock_inner_ok, dpkg_completed,
     * relock_inner_ok. execution_began (the effect_issued truth) iff the inner lock
     * was handed off; committed_ok iff dpkg completed AND the lock was re-taken. --- */

    /* the hand-off never happened: dpkg never ran, so nothing issued, nothing
     * committed — and a stale completed/relock flag must not be trusted. */
    pkgx_commit_lock_outcome o = pkgx_commit_lock_handoff(0, 0, 0);
    CHECK(o.execution_began == 0 && o.committed_ok == 0,
          "handoff: no unlock -> not begun, not committed");
    o = pkgx_commit_lock_handoff(0, 1, 1);
    CHECK(o.execution_began == 0 && o.committed_ok == 0,
          "handoff: no unlock, stale completed/relock flags ignored");

    /* released, dpkg completed, re-took the inner lock: the clean commit. */
    o = pkgx_commit_lock_handoff(1, 1, 1);
    CHECK(o.execution_began == 1 && o.committed_ok == 1,
          "handoff: unlock + completed + relock -> begun + committed");

    /* released, dpkg completed, but the re-lock FAILED: fail-closed (not committed)
     * yet effect_issued stays honest — dpkg already ran. */
    o = pkgx_commit_lock_handoff(1, 1, 0);
    CHECK(o.execution_began == 1 && o.committed_ok == 0,
          "handoff: relock failure -> fail-closed, effect_issued still honest");

    /* released, dpkg FAILED: began (effect issued), not committed. */
    o = pkgx_commit_lock_handoff(1, 0, 1);
    CHECK(o.execution_began == 1 && o.committed_ok == 0,
          "handoff: dpkg failed -> begun but not committed");
    o = pkgx_commit_lock_handoff(1, 0, 0);
    CHECK(o.execution_began == 1 && o.committed_ok == 0,
          "handoff: dpkg failed and relock failed -> begun, not committed");

    printf("%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
