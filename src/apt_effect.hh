/* The per-mechanism effectors: open the locked libapt context, resolve/read the
 * plan, spend the effect receipt over the authenticated transport, and commit
 * ONLY on a validated redeem_ok — in that same locked context (the digested plan
 * is the committed plan; runix docs/libapt-pkg-helper-plan.md §Redeem). Each is
 * the body a stage-3 per-verb entrypoint calls after env/FD hygiene and the
 * pkexec authorization check. Runtime is VM-only (root, the real broker, the
 * real dpkg lock); CI compiles and links these as the mutation-path proof. */
#ifndef PKGEXEC_APT_EFFECT_HH
#define PKGEXEC_APT_EFFECT_HH

#include "apt_status.h" /* pkgx_apt_status */
#include "redeem.h"     /* PKGX_CID_LEN */
#include "transport.h"  /* pkgx_transport */

#include <stddef.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* A. Package transactions: install / remove / purge / upgrade / dist_upgrade.
 * `verb` is the entrypoint's compile-time apt.* string; `targets` the requested
 * packages. On PKGX_APT_OK, out_cid holds the validated correlation id. */
pkgx_apt_status pkgx_apt_txn_effect(
    const char *verb, const char *const *targets, size_t ntargets,
    const char *effect_receipt, uid_t principal_uid, int plan_schema,
    const char *expected_cid, int lock_timeout_s, pkgx_transport *tx,
    char out_cid[PKGX_CID_LEN + 1], const char **detail);

/* B. update: a source-list refresh (ListUpdate). `resource_token` is "" for a
 * full refresh or the sorted source ids for a subset. No dep resolve, no dpkg. */
pkgx_apt_status pkgx_apt_update_effect(
    const char *resource_token, const char *effect_receipt, uid_t principal_uid,
    int plan_schema, const char *expected_cid, int lock_timeout_s,
    pkgx_transport *tx, char out_cid[PKGX_CID_LEN + 1], const char **detail);

/* C. hold / unhold: a dpkg selection-state change over `targets`. `verb` is
 * "apt.hold" or "apt.unhold". Ownership applies; no pkgAcquire, no DoInstall. */
pkgx_apt_status pkgx_apt_hold_effect(
    const char *verb, const char *const *targets, size_t ntargets,
    const char *effect_receipt, uid_t principal_uid, int plan_schema,
    const char *expected_cid, int lock_timeout_s, pkgx_transport *tx,
    char out_cid[PKGX_CID_LEN + 1], const char **detail);

/* D. configure: finish the pending-configuration set (dpkg --configure
 * --pending). Ownership applies (maintainer scripts run); no resolver. */
pkgx_apt_status pkgx_apt_configure_effect(
    const char *effect_receipt, uid_t principal_uid, int plan_schema,
    const char *expected_cid, int lock_timeout_s, pkgx_transport *tx,
    char out_cid[PKGX_CID_LEN + 1], const char **detail);

#ifdef __cplusplus
}
#endif

#endif /* PKGEXEC_APT_EFFECT_HH */
