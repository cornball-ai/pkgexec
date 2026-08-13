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
