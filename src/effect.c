/* The commit gate. See effect.h. Deliberately the whole of the commit-vs-refuse
 * decision, so the security property is one readable switch. */
#include "effect.h"

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
