/* The per-verb entrypoint, compiled once per verb with the verb baked in as a
 * compile-time constant (-DPKGX_VERB="apt.install" -DPKGX_FAMILY_TXN). There are
 * nine builds — runix-apt-{install,remove,purge,upgrade,dist-upgrade,update,
 * hold,unhold,configure} — each the target of one polkit action. The verb is NEVER
 * read from argv: a binary can only ever perform its own verb, so no authorized
 * low-risk action (e.g. update) can be coerced into a high-risk one by argument
 * substitution. argv is ignored entirely.
 *
 * Flow: read the trusted PKEXEC_UID (before the env is scrubbed) → parse the
 * strict stdin request for THIS verb → scrub env / neutralize stdin / close
 * inherited fds (fail closed) → drive the matching effector over the authenticated
 * broker transport → emit the strict result JSON (with effect_issued) on stdout.
 *
 * pkexec runs this as root after the polkit check; it commits nothing without a
 * real redeem_ok, so its runtime is exercised only on a disposable VM. CI compiles
 * and links all nine as the mutation-path proof. */
#ifndef PKGX_VERB
#error "PKGX_VERB must be defined at compile time, e.g. -DPKGX_VERB=\"apt.install\""
#endif

#include "apt_effect.hh" /* C-compatible: extern "C" effector prototypes */
#include "harden.h"
#include "request.h"
#include "result.h"
#include "transport.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(void) {
    /* The verb is fixed at build time. argv is deliberately never consulted. */
    const char *verb = PKGX_VERB;

    /* Trusted uid first — before the environment is scrubbed. */
    uid_t uid = 0;
    if (pkgx_read_pkexec_uid(&uid) != 0) {
        fprintf(stderr, "PKEXEC_UID missing or invalid\n");
        return 1;
    }

    /* Parse the request off fd 0 while it is still the caller's pipe. */
    char *body = NULL;
    size_t len = 0;
    const char *ec = NULL;
    if (pkgx_read_stdin(STDIN_FILENO, &body, &len, &ec) != 0) {
        fprintf(stderr, "stdin: %s\n", ec ? ec : "io");
        return 1;
    }
    pkgx_request req;
    const char *pe = NULL;
    int prc = pkgx_parse_request(verb, body, len, &req, &pe);
    pkgx_secure_wipe(body, len); /* the body carried the receipt */
    free(body);
    if (prc != 0) {
        fprintf(stderr, "parse: %s\n", pe ? pe : "schema_invalid");
        return 1;
    }

    /* Hygiene before any dpkg/maintainer script runs — fail closed. */
    if (pkgx_scrub_env() != 0 || pkgx_null_stdin() != 0 ||
        pkgx_cloexec_from(3) != 0) {
        pkgx_request_free(&req);
        fprintf(stderr, "hygiene: environment/fd hardening failed\n");
        return 1;
    }

    pkgx_transport tx;
    memset(&tx, 0, sizeof tx);
    tx.socket_path = PKGX_BROKER_SOCKET;
    tx.required_peer_uid = 0; /* the broker listens as root */
    tx.timeout_ms = PKGX_TRANSPORT_TIMEOUT_MS;

    char out_cid[PKGX_CID_LEN + 1] = {0};
    int issued = 0;
    const char *detail = "";
    pkgx_apt_status st;
#if defined(PKGX_FAMILY_TXN)
    st = pkgx_apt_txn_effect(verb, (const char *const *) req.packages,
                             req.npackages, req.effect_receipt, uid,
                             (int) req.plan_schema, req.correlation_id,
                             (int) req.lock_timeout, &tx, out_cid, &issued, &detail);
#elif defined(PKGX_FAMILY_UPDATE)
    /* v1 update is whole-source-list only; the request carries no subset. */
    st = pkgx_apt_update_effect("", req.effect_receipt, uid, (int) req.plan_schema,
                                req.correlation_id, (int) req.lock_timeout, &tx,
                                out_cid, &issued, &detail);
#elif defined(PKGX_FAMILY_HOLD)
    st = pkgx_apt_hold_effect(verb, (const char *const *) req.packages,
                              req.npackages, req.effect_receipt, uid,
                              (int) req.plan_schema, req.correlation_id,
                              (int) req.lock_timeout, &tx, out_cid, &issued, &detail);
#elif defined(PKGX_FAMILY_CONFIGURE)
    st = pkgx_apt_configure_effect(req.effect_receipt, uid, (int) req.plan_schema,
                                   req.correlation_id, (int) req.lock_timeout, &tx,
                                   out_cid, &issued, &detail);
#else
#error "define exactly one PKGX_FAMILY_{TXN,UPDATE,HOLD,CONFIGURE}"
#endif

    /* The result channel: one strict JSON object with a first-class effect_issued. */
    char result[512];
    if (pkgx_result_json(st, issued, out_cid, detail, result, sizeof result) < 0) {
        pkgx_request_free(&req);
        fprintf(stderr, "result: could not serialize\n");
        return 1;
    }
    printf("%s\n", result);
    pkgx_request_free(&req);
    return (st == PKGX_APT_OK || st == PKGX_APT_NO_OP) ? 0 : 1;
}
