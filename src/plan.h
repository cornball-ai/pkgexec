/* The plan step for each mechanism: enforce mechanism-specific policy, compute
 * the canonical resource and schema-1 digest, and spend the effect receipt
 * (redeem) with correlation_id equality — stopping short of any commit. The
 * commit that a PKGX_PLAN_OK authorizes is gated separately (effect.h), so this
 * layer stays pure over the record structs + an injectable redeem transport and
 * is fully unit-tested; the libapt locked resolve that produces the records is
 * the VM-gated C++ effector. One function per mechanism: package transactions
 * (install/remove/purge/upgrade/dist_upgrade), update, hold/unhold, configure. */
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

/* apt.update: a source-list refresh. No package policy (nothing is installed or
 * removed); the digest binds the configured source set. `resource_token` is the
 * caller-chosen resource ("" for a full refresh, or the sorted source ids for a
 * subset) — R and the helper derive it identically. NULL is treated as "". */
pkgx_plan_result pkgx_plan_and_redeem_update(
    const pkgx_src_record *srcs, size_t nsrcs, const char *resource_token,
    const char *effect_receipt, uid_t principal_uid, int plan_schema,
    const char *expected_cid, pkgx_redeem_transport tx, void *ctx,
    char out_cid[PKGX_CID_LEN + 1], const char **detail);

/* apt.hold / apt.unhold: a selection-state change. Only ownership applies — the
 * helper must never touch a rapt-owned (`r-*`) package — so a rapt-owned record
 * is PKGX_PLAN_NOT_OWNED with *detail set to it. `verb` is "apt.hold" or
 * "apt.unhold"; `targets` gives the resource, `holds` the digest. */
pkgx_plan_result pkgx_plan_and_redeem_hold(
    const char *verb, const pkgx_hold_record *holds, size_t nholds,
    const char *const *targets, size_t ntargets, const char *effect_receipt,
    uid_t principal_uid, int plan_schema, const char *expected_cid,
    pkgx_redeem_transport tx, void *ctx, char out_cid[PKGX_CID_LEN + 1],
    const char **detail);

/* apt.configure: finish the pending-configuration set (`dpkg --configure -a`).
 * The set is not selectable, but ownership still applies — configuring an r-*
 * package runs its maintainer scripts — so a rapt-owned member is
 * PKGX_PLAN_NOT_OWNED (detail = it) before the receipt is spent. The
 * broken-state check is post-commit (C++ effector). resource is the fixed token
 * "pending"; the digest binds the pending set. */
pkgx_plan_result pkgx_plan_and_redeem_configure(
    const pkgx_cfg_record *cfgs, size_t ncfgs, const char *effect_receipt,
    uid_t principal_uid, int plan_schema, const char *expected_cid,
    pkgx_redeem_transport tx, void *ctx, char out_cid[PKGX_CID_LEN + 1],
    const char **detail);

#endif /* PKGEXEC_PLAN_H */
