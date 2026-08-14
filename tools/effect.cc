/* VM-only committing diagnostic for the four commit effectors — a faithful
 * preview of the stage-3 per-verb entrypoints, without the pkexec/polkit wrapper
 * or installation. It reads PKEXEC_UID, parses the real stdin request, scrubs the
 * environment, nulls stdin, closes inherited fds, then dispatches on the verb to
 * the matching effector (A transactions / B update / C hold-unhold / D configure)
 * over the authenticated broker transport and prints the outcome. It is NOT
 * installed and it commits nothing without a real redeem_ok: it needs root, the
 * real broker socket, and a valid receipt on stdin, so it runs only on a
 * disposable VM. CI compiles+links it as the mutation-path proof.
 *
 *   make effect
 *   printf '{"effect_receipt":"...","correlation_id":"...","plan_schema":1,
 *           "packages":["nginx"],"lock_timeout":30}' \
 *     | sudo PKEXEC_UID=1000 ./pkgexec-effect apt.install     # VM only
 *   # verb selects the mechanism: apt.install/remove/purge/upgrade/dist_upgrade
 *   # (A), apt.update (B), apt.hold/apt.unhold (C), apt.configure (D).
 */
#include "../src/apt_effect.hh"
#include "../src/harden.h"
#include "../src/redeem.h"
#include "../src/request.h"
#include "../src/result.h"
#include "../src/transport.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Same uniform result channel as the real entrypoint (this diagnostic mirrors
 * it): every helper-executed failure emits an internal result with
 * effect_issued=false; stderr is only for a failure to emit the record itself. */
static int fail_result(int rfd, const char *cid, const char *detail) {
    if (pkgx_result_emit(rfd, PKGX_APT_INTERNAL, 0, cid, detail) != 0) {
        fprintf(stderr, "result: could not emit\n");
    }
    return 1;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: pkgexec-effect <apt.verb>  (request on stdin)\n");
        return 2; /* a CLI usage error, not a helper-executed failure */
    }
    const char *verb = argv[1];

    /* Isolate the result channel BEFORE anything runs, exactly like the entrypoint:
     * fd 1 becomes stderr and the strict JSON result goes only to a dedicated
     * close-on-exec fd, so no effector / libapt / spawned dpkg output pollutes it. */
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

    /* Parse the request off fd 0 while it is still the caller's pipe. */
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
        return fail_result(rfd, "", pe ? pe : "schema_invalid");
    }

    /* Hygiene before any dpkg/maintainer script runs — fail closed: a privileged
     * entrypoint must refuse if the environment cannot be scrubbed, stdin cannot
     * be neutralized, or inherited descriptors cannot be closed. */
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
    const char *detail = "";
    int issued = 0;
    pkgx_apt_status st;
    if (strcmp(verb, "apt.update") == 0) {
        /* Full refresh (resource ""); a subset token is a stage-3 entrypoint arg. */
        st = pkgx_apt_update_effect("", req.effect_receipt, uid,
                                    (int) req.plan_schema, req.correlation_id,
                                    (int) req.lock_timeout, &tx, out_cid, &issued,
                                    &detail);
    } else if (strcmp(verb, "apt.hold") == 0 || strcmp(verb, "apt.unhold") == 0) {
        st = pkgx_apt_hold_effect(
            verb, (const char *const *) req.packages, req.npackages,
            req.effect_receipt, uid, (int) req.plan_schema, req.correlation_id,
            (int) req.lock_timeout, &tx, out_cid, &issued, &detail);
    } else if (strcmp(verb, "apt.configure") == 0) {
        st = pkgx_apt_configure_effect(req.effect_receipt, uid,
                                       (int) req.plan_schema, req.correlation_id,
                                       (int) req.lock_timeout, &tx, out_cid,
                                       &issued, &detail);
    } else {
        st = pkgx_apt_txn_effect(
            verb, (const char *const *) req.packages, req.npackages,
            req.effect_receipt, uid, (int) req.plan_schema, req.correlation_id,
            (int) req.lock_timeout, &tx, out_cid, &issued, &detail);
    }

    /* The result channel: exactly the strict JSON a stage-3 entrypoint emits,
     * written in full over the same helper path. */
    int emitted = pkgx_result_emit(rfd, st, issued, out_cid, detail);
    pkgx_request_free(&req);
    if (emitted != 0) {
        fprintf(stderr, "result: could not emit\n");
        return 1;
    }
    return (st == PKGX_APT_OK || st == PKGX_APT_NO_OP) ? 0 : 1;
}
