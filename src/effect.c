/* The commit gate. See effect.h. Deliberately the whole of the commit-vs-refuse
 * decision, so the security property is one readable switch. */
#include "effect.h"

#include "request.h" /* pkgx_cid_valid */

#include <stddef.h>

pkgx_effect_status pkgx_effect_gate(pkgx_plan_result pr, const char *validated_cid,
                                    pkgx_committer commit, void *commit_ctx) {
    switch (pr) {
    case PKGX_PLAN_OK:
        /* A validated redeem_ok (correlation_id == the request's) is the only
         * result that reaches here as OK; commit in the retained context. */
        if (commit == NULL) {
            return PKGX_EFFECT_COMMIT_FAILED; /* fail closed, never silent-ok */
        }
        /* Do not commit under a missing or malformed cid: the committer stamps
         * it into the native transaction record, so revalidate the exact grammar
         * here rather than trust the enum. */
        if (!pkgx_cid_valid(validated_cid)) {
            return PKGX_EFFECT_COMMIT_FAILED;
        }
        if (commit(commit_ctx, validated_cid) != 0) {
            return PKGX_EFFECT_COMMIT_FAILED;
        }
        return PKGX_EFFECT_OK;
    case PKGX_PLAN_NO_OP:
        return PKGX_EFFECT_NO_OP;
    default:
        /* NOT_OWNED / HELD / PROTECTED / NO_INTENT / INTERNAL: no commit. */
        return PKGX_EFFECT_REFUSED;
    }
}
