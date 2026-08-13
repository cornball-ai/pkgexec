/* The per-mechanism effectors: open the locked libapt context, resolve/read the
 * plan, spend the effect receipt over the authenticated transport, and commit
 * ONLY on a validated redeem_ok — in that same locked context (the digested plan
 * is the committed plan; runix docs/libapt-pkg-helper-plan.md §Redeem). Each is
 * the body a stage-3 per-verb entrypoint calls after env/FD hygiene and the
 * pkexec authorization check. Runtime is VM-only (root, the real broker, the
 * real dpkg lock); CI compiles and links these as the mutation-path proof. */
#ifndef PKGEXEC_APT_EFFECT_HH
#define PKGEXEC_APT_EFFECT_HH

#include "redeem.h"    /* PKGX_CID_LEN */
#include "transport.h" /* pkgx_transport */

#include <stddef.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* The effector outcome; a stage-3 entrypoint maps each to the runix_* condition
 * on the helper's stdout result object (plan §5 error table). */
typedef enum {
    PKGX_APT_OK = 0,         /* redeemed and committed */
    PKGX_APT_NO_OP,          /* nothing to do; the receipt is left unspent */
    PKGX_APT_LOCKED,         /* dpkg frontend lock not taken in the window */
    PKGX_APT_NOT_OWNED,      /* a rapt-owned (r-*) package is in the plan */
    PKGX_APT_HELD,           /* a held package would change */
    PKGX_APT_PROTECTED,      /* an essential/protected package would be removed */
    PKGX_APT_NO_INTENT,      /* redeem refused / cid mismatch / protocol */
    PKGX_APT_RESOLVE_FAILED, /* unknown package, or apt could not resolve */
    PKGX_APT_COMMIT_FAILED,  /* GetArchives/DoInstall or the dpkg pass failed */
    PKGX_APT_BROKEN,         /* committed, but the dpkg database is left broken */
    PKGX_APT_INTERNAL        /* init / digest / allocation failure */
} pkgx_apt_status;

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
