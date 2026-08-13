/* The per-mechanism plan step. See plan.h. */
#include "plan.h"

#include "policy.h"

#include <stdlib.h>

/* Shared redeem tail: spend the receipt bound to {verb, resource, schema, hash}
 * and require the reply's correlation_id to equal expected_cid. resource/hash
 * are borrowed. Returns PKGX_PLAN_OK (validated cid in out_cid) or
 * PKGX_PLAN_NO_INTENT (*detail = the redeem code). */
static pkgx_plan_result redeem_tail(const char *verb, const char *resource,
                                    const char *hash, const char *effect_receipt,
                                    uid_t principal_uid, int plan_schema,
                                    const char *expected_cid,
                                    pkgx_redeem_transport tx, void *ctx,
                                    char out_cid[PKGX_CID_LEN + 1],
                                    const char **detail) {
    pkgx_redeem_req req = {effect_receipt, principal_uid, verb,
                           resource,       plan_schema,   hash};
    const char *code = "";
    pkgx_redeem_status rs =
        pkgx_redeem(&req, expected_cid, tx, ctx, out_cid, &code);
    if (rs == PKGX_REDEEM_OK) {
        *detail = "ok";
        return PKGX_PLAN_OK;
    }
    *detail = code; /* refused / cid_mismatch / protocol / transport */
    return PKGX_PLAN_NO_INTENT;
}

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
    pkgx_plan_result r =
        redeem_tail(verb, resource, hash, effect_receipt, principal_uid,
                    plan_schema, expected_cid, tx, ctx, out_cid, detail);
    free(resource);
    return r;
}

pkgx_plan_result pkgx_plan_and_redeem_update(
    const pkgx_src_record *srcs, size_t nsrcs, const char *resource_token,
    const char *effect_receipt, uid_t principal_uid, int plan_schema,
    const char *expected_cid, pkgx_redeem_transport tx, void *ctx,
    char out_cid[PKGX_CID_LEN + 1], const char **detail) {
    *detail = "";
    if (nsrcs == 0) {
        *detail = "no_op";
        return PKGX_PLAN_NO_OP;
    }
    /* No package policy: a source refresh installs and removes nothing. */
    char hash[PKGEXEC_DIGEST_HEX + 1];
    if (pkgx_digest_update(srcs, nsrcs, hash, NULL, NULL) != 0) {
        return PKGX_PLAN_INTERNAL;
    }
    const char *resource = (resource_token != NULL) ? resource_token : "";
    return redeem_tail("apt.update", resource, hash, effect_receipt,
                       principal_uid, plan_schema, expected_cid, tx, ctx,
                       out_cid, detail);
}

pkgx_plan_result pkgx_plan_and_redeem_hold(
    const char *verb, const pkgx_hold_record *holds, size_t nholds,
    const char *const *targets, size_t ntargets, const char *effect_receipt,
    uid_t principal_uid, int plan_schema, const char *expected_cid,
    pkgx_redeem_transport tx, void *ctx, char out_cid[PKGX_CID_LEN + 1],
    const char **detail) {
    *detail = "";
    if (nholds == 0) {
        *detail = "no_op";
        return PKGX_PLAN_NO_OP;
    }
    /* Ownership is the only policy for a selection-state change: pkgexec must
     * never hold/unhold a rapt-owned package. Check before spending the receipt. */
    for (size_t i = 0; i < nholds; i++) {
        const char *nm = holds[i].package != NULL ? holds[i].package : "";
        if (pkgx_is_rapt_owned(nm)) {
            *detail = holds[i].package;
            return PKGX_PLAN_NOT_OWNED;
        }
    }
    char *resource = NULL;
    if (pkgx_resource(targets, ntargets, &resource) != 0) {
        return PKGX_PLAN_INTERNAL;
    }
    char hash[PKGEXEC_DIGEST_HEX + 1];
    if (pkgx_digest_hold(verb, holds, nholds, hash, NULL, NULL) != 0) {
        free(resource);
        return PKGX_PLAN_INTERNAL;
    }
    pkgx_plan_result r =
        redeem_tail(verb, resource, hash, effect_receipt, principal_uid,
                    plan_schema, expected_cid, tx, ctx, out_cid, detail);
    free(resource);
    return r;
}

pkgx_plan_result pkgx_plan_and_redeem_configure(
    const pkgx_cfg_record *cfgs, size_t ncfgs, const char *effect_receipt,
    uid_t principal_uid, int plan_schema, const char *expected_cid,
    pkgx_redeem_transport tx, void *ctx, char out_cid[PKGX_CID_LEN + 1],
    const char **detail) {
    *detail = "";
    if (ncfgs == 0) {
        *detail = "no_op";
        return PKGX_PLAN_NO_OP;
    }
    /* The pending-config set is not selectable, so no pre-commit package policy;
     * the broken-state check is post-commit (C++ effector). */
    char hash[PKGEXEC_DIGEST_HEX + 1];
    if (pkgx_digest_configure(cfgs, ncfgs, hash, NULL, NULL) != 0) {
        return PKGX_PLAN_INTERNAL;
    }
    return redeem_tail("apt.configure", "pending", hash, effect_receipt,
                       principal_uid, plan_schema, expected_cid, tx, ctx,
                       out_cid, detail);
}
