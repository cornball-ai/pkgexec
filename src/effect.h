/* The commit gate: the single place where a host mutation is authorized, and
 * only on a validated redemption. A verb's plan step (plan.h) returns a
 * pkgx_plan_result; this gate turns that result into a commit decision, running
 * the caller's committer EXACTLY when the plan redeemed OK (a redeem_ok whose
 * correlation_id already equalled the request's, enforced in redeem.c) — and
 * for no other result. Keeping this tiny and pure is the point: the property
 * "commit happens only after a valid redeem_ok" is checkable by reading one
 * function.
 *
 * The committer performs the actual libapt mutation and MUST run in the same
 * locked cache/dep-cache context that produced the redeemed plan_hash (the
 * digested plan is the committed plan — runix docs/libapt-pkg-helper-plan.md
 * §Redeem). The C++ effector owns that context and passes it as the committer's
 * ctx; this gate never touches libapt itself, so it stays fully unit-tested. */
#ifndef PKGEXEC_EFFECT_H
#define PKGEXEC_EFFECT_H

#include "plan.h"   /* pkgx_plan_result */
#include "redeem.h" /* PKGX_CID_LEN */

#ifdef __cplusplus
extern "C" {
#endif

/* Perform the verb's host mutation in the caller's retained libapt context.
 * `correlation_id` is the validated cid, to stamp into apt's native
 * transaction record. Returns 0 on success, non-zero on any commit failure. */
typedef int (*pkgx_committer)(void *ctx, const char *correlation_id);

typedef enum {
    PKGX_EFFECT_OK = 0,        /* redeemed and committed */
    PKGX_EFFECT_NO_OP,         /* empty plan: nothing redeemed, nothing committed */
    PKGX_EFFECT_REFUSED,       /* policy or redeem refused: nothing committed */
    PKGX_EFFECT_COMMIT_FAILED  /* redeem_ok, but the committer failed */
} pkgx_effect_status;

/* Invoke `commit` iff `pr == PKGX_PLAN_OK`, handing it `validated_cid`; any
 * other plan result commits nothing. A NULL committer on an OK plan is a
 * programming error and fails closed as PKGX_EFFECT_COMMIT_FAILED (never a
 * silent success). This is the only sanctioned path to a commit. */
pkgx_effect_status pkgx_effect_gate(pkgx_plan_result pr, const char *validated_cid,
                                    pkgx_committer commit, void *commit_ctx);

#ifdef __cplusplus
}
#endif

#endif /* PKGEXEC_EFFECT_H */
