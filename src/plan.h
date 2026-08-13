/* The non-committing plan step: enforce policy on the resolved transaction,
 * compute the canonical resource and schema-1 digest, and spend the effect
 * receipt (redeem) with correlation_id equality — stopping short of any commit.
 * Pure over the record structs + an injectable redeem transport, so it is fully
 * unit-tested; the libapt locked resolve that produces the records is the
 * VM-gated `tools/plan.cc` diagnostic. Transaction verbs only (install/remove/
 * purge/upgrade/dist_upgrade); hold/configure/update arrive with activation. */
#ifndef PKGEXEC_PLAN_H
#define PKGEXEC_PLAN_H

#include "digest.h"
#include "redeem.h"

#include <stddef.h>
#include <sys/types.h>

typedef enum {
    PKGX_PLAN_OK = 0,      /* policy passed, receipt redeemed: a commit would follow */
    PKGX_PLAN_NO_OP,       /* empty resolved transaction: no effect, receipt unspent */
    PKGX_PLAN_NOT_OWNED,   /* rapt-owned package in the plan */
    PKGX_PLAN_HELD,        /* a held package would change */
    PKGX_PLAN_PROTECTED,   /* Essential/protected removal */
    PKGX_PLAN_NO_INTENT,   /* redeem refused / cid mismatch / protocol -> no commit */
    PKGX_PLAN_INTERNAL     /* digest/resource construction failed */
} pkgx_plan_result;

/* Runs, in order: policy over `recs`; resource from `targets`; schema-1 digest
 * from `recs`; redeem the receipt bound to {verb, resource, plan_schema, digest}
 * with `expected_cid` equality. Policy is checked BEFORE redemption, so a refused
 * plan never spends a receipt. On PKGX_PLAN_OK the validated cid is in out_cid.
 * `*detail` is the offending package (policy) or the redeem code (no_intent). */
pkgx_plan_result pkgx_plan_and_redeem(
    const char *verb, const pkgx_txn_record *recs, size_t nrecs,
    const char *const *targets, size_t ntargets, const char *effect_receipt,
    uid_t principal_uid, int plan_schema, const char *expected_cid,
    pkgx_redeem_transport tx, void *ctx, char out_cid[PKGX_CID_LEN + 1],
    const char **detail);

#endif /* PKGEXEC_PLAN_H */
