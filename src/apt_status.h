/* The effector outcome, and the pure post-effect classifier. A stage-3
 * entrypoint maps each status to the runix_* condition on the helper's stdout
 * result (plan §5). Splitting the classifier out of the libapt effector keeps
 * the "what actually happened to the host" decision testable without root or
 * dpkg — the case that matters (fetch failed before any change vs dpkg ran and
 * left the db broken) is exercised directly. */
#ifndef PKGEXEC_APT_STATUS_H
#define PKGEXEC_APT_STATUS_H

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    PKGX_APT_OK = 0,         /* redeemed and committed; the db is consistent */
    PKGX_APT_NO_OP,          /* nothing to do; the receipt is left unspent */
    PKGX_APT_LOCKED,         /* dpkg frontend lock not taken in the window */
    PKGX_APT_NOT_OWNED,      /* a rapt-owned (r-*) package is in the plan */
    PKGX_APT_HELD,           /* a held package would change */
    PKGX_APT_PROTECTED,      /* an essential/protected package would be removed */
    PKGX_APT_NO_INTENT,      /* redeem refused / cid mismatch / protocol */
    PKGX_APT_RESOLVE_FAILED, /* unknown package, or apt could not resolve */
    PKGX_APT_NOT_APPLIED,    /* receipt spent, but the effect never reached dpkg
                              * (archive fetch or setup failed): host unchanged */
    PKGX_APT_COMMIT_FAILED,  /* dpkg ran and failed, but left a consistent db */
    PKGX_APT_BROKEN,         /* dpkg ran and left the db broken/incomplete */
    PKGX_APT_INTERNAL        /* init / digest / gate inconsistency */
} pkgx_apt_status;

/* Classify a package-transaction outcome from what actually happened, read as
 * booleans (0/1):
 *   committer_entered — the gate admitted the commit (validated redeem_ok);
 *   execution_began   — DoInstall was invoked, i.e. dpkg actually ran;
 *   committed_ok      — DoInstall returned Completed;
 *   broken            — post-effect dpkg ground truth has broken packages
 *                       (meaningful only once execution_began).
 * Distinguishes a pre-effect failure (nothing applied) from a dpkg run that
 * left the system broken, and only trusts `broken` after execution began.
 *
 * Configure (D) reuses this: its commit is a single dpkg --configure --pending
 * with no fetch phase, so execution_began == committer_entered, committed_ok is
 * dpkg's exit, and broken is the shared incomplete-state scan — the same OK /
 * COMMIT_FAILED / BROKEN distinction, over configure's own ground truth. */
pkgx_apt_status pkgx_txn_classify(int committer_entered, int execution_began,
                                  int committed_ok, int broken);

/* Classify an update (list-refresh) outcome — its OWN ground truth, not A's dpkg
 * scan (update runs no dpkg and can never leave the database broken):
 *   committer_entered — the gate admitted the refresh (validated redeem_ok);
 *   refresh_ok        — ListUpdate() reported success;
 *   indexes_readable  — a fresh cache re-opened over the refreshed indexes.
 * OK iff the refresh succeeded AND the new indexes read back; a failed or partial
 * refresh that still leaves the previous indexes usable is COMMIT_FAILED
 * (operation failed, host consistent), never BROKEN. */
pkgx_apt_status pkgx_update_classify(int committer_entered, int refresh_ok,
                                     int indexes_readable);

/* Classify a hold/unhold (selection-state) outcome — its OWN ground truth, the
 * dpkg selection read back after the write (not A's dpkg scan; a selection change
 * runs no maintainer scripts and cannot leave the database broken):
 *   committer_entered  — the gate admitted the write (validated redeem_ok);
 *   selection_applied  — dpkg --set-selections exited 0;
 *   selection_matches  — every changed target reads back in the intended state.
 * OK iff the write succeeded AND the read-back confirms it; otherwise
 * COMMIT_FAILED (operation failed, prior selections intact), never BROKEN. */
pkgx_apt_status pkgx_hold_classify(int committer_entered, int selection_applied,
                                   int selection_matches);

#ifdef __cplusplus
}
#endif

#endif /* PKGEXEC_APT_STATUS_H */
