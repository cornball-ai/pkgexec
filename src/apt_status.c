/* See apt_status.h. The whole post-effect decision, kept pure. */
#include "apt_status.h"

pkgx_apt_status pkgx_txn_classify(int committer_entered, int execution_began,
                                  int committed_ok, int broken) {
    if (!committer_entered) {
        /* The gate refused an OK plan (NULL committer or a cid that failed
         * revalidation): the commit never started and nothing is inconsistent
         * on the host, but the plan said OK — treat it as an internal fault. */
        return PKGX_APT_INTERNAL;
    }
    if (!execution_began) {
        /* Setup or the archive fetch failed before dpkg ran: the receipt was
         * spent, but the host was not touched. */
        return PKGX_APT_NOT_APPLIED;
    }
    if (broken) {
        /* dpkg ran and left unmet dependencies — a partial/interrupted effect. */
        return PKGX_APT_BROKEN;
    }
    if (committed_ok) {
        return PKGX_APT_OK;
    }
    /* dpkg reported failure but left the database consistent (e.g. a maintainer
     * script failed and unwound cleanly). */
    return PKGX_APT_COMMIT_FAILED;
}

pkgx_apt_status pkgx_update_classify(int committer_entered, int refresh_ok,
                                     int indexes_readable) {
    if (!committer_entered) {
        return PKGX_APT_INTERNAL; /* gate refused an OK plan: see pkgx_txn_classify */
    }
    if (refresh_ok && indexes_readable) {
        return PKGX_APT_OK;
    }
    /* The refresh failed, or the rebuilt indexes will not read back. No dpkg ran,
     * so nothing is broken — the previous indexes remain usable; the operation
     * simply did not complete. */
    return PKGX_APT_COMMIT_FAILED;
}

pkgx_apt_status pkgx_hold_classify(int committer_entered, int selection_applied,
                                   int selection_matches) {
    if (!committer_entered) {
        return PKGX_APT_INTERNAL; /* gate refused an OK plan: see pkgx_txn_classify */
    }
    if (selection_applied && selection_matches) {
        return PKGX_APT_OK;
    }
    /* dpkg --set-selections failed, or the read-back does not show the intended
     * state. A selection write runs no maintainer scripts, so the database is
     * never left broken; the prior selections stand. */
    return PKGX_APT_COMMIT_FAILED;
}

pkgx_commit_lock_outcome pkgx_commit_lock_handoff(int unlock_inner_ok,
                                                  int dpkg_completed,
                                                  int relock_inner_ok) {
    pkgx_commit_lock_outcome o;
    /* No hand-off means the child never ran: nothing issued, nothing committed. */
    o.execution_began = unlock_inner_ok ? 1 : 0;
    /* A clean commit needs dpkg to complete AND the inner lock re-taken; a re-lock
     * failure is fail-closed (not OK) even when dpkg itself completed. */
    o.committed_ok =
        (unlock_inner_ok && dpkg_completed && relock_inner_ok) ? 1 : 0;
    return o;
}
