/* Trusted-side policy enforcement over a resolved apt transaction, applied to
 * the whole plan (target + every pulled dependency) as the digest sees it. The
 * unprivileged preview is advisory; this is what the helper enforces before it
 * would commit. Pure over the record structs, so it is fully unit-tested without
 * libapt (apt-mutation-boundary-contract.md, "Package ownership"). */
#ifndef PKGEXEC_POLICY_H
#define PKGEXEC_POLICY_H

#include "digest.h"

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    PKGX_POLICY_OK = 0,
    PKGX_POLICY_NOT_OWNED,  /* an r-* (rapt-owned) package is in the plan */
    PKGX_POLICY_HELD,       /* a held package would be changed */
    PKGX_POLICY_PROTECTED   /* an Essential/protected package would be removed */
} pkgx_policy_result;

/* Check ownership, holds, and protection over the resolved records. Returns
 * PKGX_POLICY_OK, or the first violation (ownership first, then holds, then
 * protection); *offender is set to the offending package name (borrowed from
 * recs) on a violation, or NULL on OK. */
pkgx_policy_result pkgx_policy_check(const pkgx_txn_record *recs, size_t n,
                                     const char **offender);

/* rapt's exact ownership predicate, pinned here: ^r-[a-z]+-[a-z0-9.]+$ (kept
 * honest against rapt by a cross-repo test). Exposed for that test. */
int pkgx_is_rapt_owned(const char *name);

#ifdef __cplusplus
}
#endif

#endif /* PKGEXEC_POLICY_H */
