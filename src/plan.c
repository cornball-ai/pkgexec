/* The non-committing plan step. See plan.h. */
#include "plan.h"

#include "policy.h"

#include <stdlib.h>

pkgx_plan_result pkgx_plan_and_redeem(
    const char *verb, const pkgx_txn_record *recs, size_t nrecs,
    const char *const *targets, size_t ntargets, const char *effect_receipt,
    uid_t principal_uid, int plan_schema, const char *expected_cid,
    pkgx_redeem_transport tx, void *ctx, char out_cid[PKGX_CID_LEN + 1],
    const char **detail) {
    *detail = "";

    /* An empty resolved transaction is a no-op (already-current install, absent
     * removal): no effect is issued, so the receipt is left unspent. */
    if (nrecs == 0) {
        *detail = "no_op";
        return PKGX_PLAN_NO_OP;
    }

    /* Policy first: a refused plan must never spend the receipt. */
    const char *offender = NULL;
    switch (pkgx_policy_check(recs, nrecs, &offender)) {
    case PKGX_POLICY_OK:
        break;
    case PKGX_POLICY_NOT_OWNED:
        *detail = offender;
        return PKGX_PLAN_NOT_OWNED;
    case PKGX_POLICY_HELD:
        *detail = offender;
        return PKGX_PLAN_HELD;
    case PKGX_POLICY_PROTECTED:
        *detail = offender;
        return PKGX_PLAN_PROTECTED;
    }

    char *resource = NULL;
    if (pkgx_resource(targets, ntargets, &resource) != 0) {
        return PKGX_PLAN_INTERNAL;
    }
    char hash[PKGEXEC_DIGEST_HEX + 1];
    if (pkgx_digest_pkg_txn(verb, recs, nrecs, hash, NULL, NULL) != 0) {
        free(resource);
        return PKGX_PLAN_INTERNAL;
    }

    pkgx_redeem_req req = {effect_receipt, principal_uid, verb,
                           resource,       plan_schema,   hash};
    const char *code = "";
    pkgx_redeem_status rs = pkgx_redeem(&req, expected_cid, tx, ctx, out_cid, &code);
    free(resource);

    if (rs == PKGX_REDEEM_OK) {
        *detail = "ok";
        return PKGX_PLAN_OK;
    }
    *detail = code; /* the redeem code (refused/cid_mismatch/protocol/transport) */
    return PKGX_PLAN_NO_INTENT;
}
