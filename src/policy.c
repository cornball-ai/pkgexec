/* Trusted-side policy enforcement. See policy.h. */
#include "policy.h"

#include <string.h>

/* rapt's predicate: ^r-[a-z]+-[a-z0-9.]+$ (r-pkg/R/manager.R). Pinned byte-for-
 * byte; a cross-repo test guards against drift. */
int pkgx_is_rapt_owned(const char *name) {
    if (name[0] != 'r' || name[1] != '-') {
        return 0;
    }
    const char *p = name + 2;
    const char *start = p;
    while (*p >= 'a' && *p <= 'z') {
        p++;
    }
    if (p == start || *p != '-') { /* need [a-z]+ then '-' */
        return 0;
    }
    p++;
    start = p;
    while ((*p >= 'a' && *p <= 'z') || (*p >= '0' && *p <= '9') || *p == '.') {
        p++;
    }
    if (p == start) { /* need [a-z0-9.]+ */
        return 0;
    }
    return *p == '\0';
}

static int has_flag(const pkgx_txn_record *r, const char *flag) {
    for (size_t i = 0; i < r->nflags; i++) {
        if (r->flags[i] != NULL && strcmp(r->flags[i], flag) == 0) {
            return 1;
        }
    }
    return 0;
}

static int is_removal(const char *action) {
    return action != NULL &&
           (strcmp(action, "remove") == 0 || strcmp(action, "purge") == 0);
}

pkgx_policy_result pkgx_policy_check(const pkgx_txn_record *recs, size_t n,
                                     const char **offender) {
    *offender = NULL;
    /* Ownership over the whole transaction takes precedence. */
    for (size_t i = 0; i < n; i++) {
        if (recs[i].package != NULL && pkgx_is_rapt_owned(recs[i].package)) {
            *offender = recs[i].package;
            return PKGX_POLICY_NOT_OWNED;
        }
    }
    /* A held package appearing in the resolved plan would be changed. */
    for (size_t i = 0; i < n; i++) {
        if (has_flag(&recs[i], "hold")) {
            *offender = recs[i].package;
            return PKGX_POLICY_HELD;
        }
    }
    /* Removing an Essential/protected package is refused. */
    for (size_t i = 0; i < n; i++) {
        if (is_removal(recs[i].action) &&
            (has_flag(&recs[i], "essential") || has_flag(&recs[i], "protected"))) {
            *offender = recs[i].package;
            return PKGX_POLICY_PROTECTED;
        }
    }
    return PKGX_POLICY_OK;
}
