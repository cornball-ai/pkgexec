/* Broker redeem client. The ROOT helper sends a token-addressed `redeem_receipt`
 * (no correlation_id on the wire — the broker derives it from the matched intent)
 * and strictly validates the reply before it would commit. Two guarantees live
 * here: the reply's error code must be in the closed set, and on success the
 * reply's correlation_id must equal the one the caller already holds (from the
 * intent it opened) — so a valid receipt can never be committed and logged under
 * a substituted operation id (apt-mutation-boundary-contract.md, redeem rule).
 *
 * Slice 2 is non-committing: this spends a receipt and validates the reply; no
 * host mutation happens here. The transport is injectable so the client is
 * tested with fake broker replies; the real socket/framing transport arrives
 * with the activation slice. */
#ifndef PKGEXEC_REDEEM_H
#define PKGEXEC_REDEEM_H

#include <stddef.h>
#include <sys/types.h> /* uid_t */

#define PKGX_CID_LEN 37 /* 20 digits, '-', 16 hex; +1 for the NUL */

/* The redeem request (token-addressed; carries no correlation_id). */
typedef struct {
    const char *effect_receipt; /* 32 lowercase hex */
    uid_t principal_uid;        /* PKEXEC_UID */
    const char *operation;      /* the verb, e.g. "apt.install" */
    const char *resource;       /* canonical resource */
    int plan_schema;            /* 1 */
    const char *plan_hash;      /* 64 lowercase hex */
} pkgx_redeem_req;

/* Every non-OK outcome maps to runix_no_intent at the helper boundary (no
 * commit); `*code` carries the specific reason for the audit/diagnostic. */
typedef enum {
    PKGX_REDEEM_OK = 0,       /* redeemed; correlation_id validated == expected */
    PKGX_REDEEM_REFUSED,      /* broker returned a closed-set receipt_* error */
    PKGX_REDEEM_CID_MISMATCH, /* redeem_ok but correlation_id != expected */
    PKGX_REDEEM_PROTOCOL      /* malformed/unknown reply, or transport failure */
} pkgx_redeem_status;

/* Transport: send request body `req` (reqlen bytes), return a malloc'd reply body
 * in *resp (*resplen). Returns 0 on success, -1 on I/O failure. The real
 * transport frames and talks to the broker socket; tests inject a fake. */
typedef int (*pkgx_redeem_transport)(void *ctx, const char *req, size_t reqlen,
                                     char **resp, size_t *resplen);

/* Build the request, call `tx`, strictly validate the reply, and require the
 * reply's correlation_id to equal `expected_cid`. On PKGX_REDEEM_OK the validated
 * cid is copied to out_cid. `*code` is the broker error code (REFUSED),
 * "cid_mismatch" (CID_MISMATCH), or a protocol reason (PROTOCOL). */
pkgx_redeem_status pkgx_redeem(const pkgx_redeem_req *req, const char *expected_cid,
                               pkgx_redeem_transport tx, void *ctx,
                               char out_cid[PKGX_CID_LEN + 1], const char **code);

#endif /* PKGEXEC_REDEEM_H */
