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
 * broker transport → emit the strict result JSON (with effect_issued) on a dedicated
 * close-on-exec result fd (fd 1 is redirected to stderr first, so no commit output
 * pollutes the protocol channel).
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

/* Every helper-executed failure reports through the SAME result channel: an
 * internal status, effect_issued=false (nothing ran), the correlation id if the
 * request parsed (else ""), and a detail tag. stderr is reserved for the one thing
 * the channel itself cannot report — a failure to serialize or write the record.
 * Returns the process exit code (always 1: a reported failure is still a failure). */
static int fail_result(int rfd, const char *cid, const char *detail) {
    if (pkgx_result_emit(rfd, PKGX_APT_INTERNAL, 0, cid, detail) != 0) {
        fprintf(stderr, "result: could not emit\n");
    }
    return 1;
}

int main(void) {
    /* The verb is fixed at build time. argv is deliberately never consulted. */
    const char *verb = PKGX_VERB;

    /* Isolate the result channel BEFORE anything runs: fd 1 becomes stderr, and the
     * strict JSON result is written only to a dedicated close-on-exec fd, so no
     * effector, libapt commit, or spawned dpkg can pollute the protocol channel. */
    int rfd = pkgx_result_channel_open();
    if (rfd < 0) {
        fprintf(stderr, "result: cannot isolate the result channel\n");
        return 1;
    }

    /* Trusted uid first — before the environment is scrubbed. */
    uid_t uid = 0;
    if (pkgx_read_pkexec_uid(&uid) != 0) {
        return fail_result(rfd, "", "pkexec_uid");
    }

    /* Parse the request off fd 0 while it is still the caller's pipe. The reader
     * wipes any partial buffer on error, so a receipt is never leaked. */
    char *body = NULL;
    size_t len = 0;
    const char *ec = NULL;
    if (pkgx_read_stdin(STDIN_FILENO, &body, &len, &ec) != 0) {
        return fail_result(rfd, "", ec ? ec : "stdin");
    }
    pkgx_request req;
    const char *pe = NULL;
    int prc = pkgx_parse_request(verb, body, len, &req, &pe);
    pkgx_secure_wipe(body, len); /* the body carried the receipt */
    free(body);
    if (prc != 0) {
        /* Parsing never completed: no correlation id to report. */
        return fail_result(rfd, "", pe ? pe : "schema_invalid");
    }

    /* Hygiene before any dpkg/maintainer script runs — fail closed. */
    if (pkgx_scrub_env() != 0 || pkgx_null_stdin() != 0 ||
        pkgx_cloexec_from(3) != 0) {
        int rc = fail_result(rfd, req.correlation_id, "hygiene");
        pkgx_request_free(&req);
        return rc;
    }

    pkgx_transport tx;
    memset(&tx, 0, sizeof tx);
    tx.socket_path = PKGX_BROKER_SOCKET;
    tx.required_peer_uid = 0; /* the broker listens as root */
    tx.timeout_ms = PKGX_TRANSPORT_TIMEOUT_MS;

    char out_cid[PKGX_CID_LEN + 1] = {0};
    int issued = 0;
    char detail[PKGX_DETAIL_CAP] = "";
    pkgx_apt_status st;
#if defined(PKGX_FAMILY_TXN)
    st = pkgx_apt_txn_effect(verb, (const char *const *) req.packages,
                             req.npackages, req.effect_receipt, uid,
                             (int) req.plan_schema, req.correlation_id,
                             (int) req.lock_timeout, &tx, out_cid, &issued, detail);
#elif defined(PKGX_FAMILY_UPDATE)
    /* v1 update is whole-source-list only; the request carries no subset. */
    st = pkgx_apt_update_effect("", req.effect_receipt, uid, (int) req.plan_schema,
                                req.correlation_id, (int) req.lock_timeout, &tx,
                                out_cid, &issued, detail);
#elif defined(PKGX_FAMILY_HOLD)
    st = pkgx_apt_hold_effect(verb, (const char *const *) req.packages,
                              req.npackages, req.effect_receipt, uid,
                              (int) req.plan_schema, req.correlation_id,
                              (int) req.lock_timeout, &tx, out_cid, &issued, detail);
#elif defined(PKGX_FAMILY_CONFIGURE)
    st = pkgx_apt_configure_effect(req.effect_receipt, uid, (int) req.plan_schema,
                                   req.correlation_id, (int) req.lock_timeout, &tx,
                                   out_cid, &issued, detail);
#else
#error "define exactly one PKGX_FAMILY_{TXN,UPDATE,HOLD,CONFIGURE}"
#endif

    /* The result channel: one strict JSON object with a first-class effect_issued,
     * written in full (a closed/short result pipe is a reported failure, exit 1,
     * never an apparent success). */
    int emitted = pkgx_result_emit(rfd, st, issued, out_cid, detail);
    pkgx_request_free(&req);
    if (emitted != 0) {
        fprintf(stderr, "result: could not emit\n");
        return 1;
    }
    return (st == PKGX_APT_OK || st == PKGX_APT_NO_OP) ? 0 : 1;
}
