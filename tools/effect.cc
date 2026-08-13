/* VM-only committing diagnostic for the package-transaction effector — a faithful
 * preview of the stage-3 per-verb entrypoint, without the pkexec/polkit wrapper
 * or installation. It reads PKEXEC_UID, parses the real stdin request, scrubs the
 * environment, nulls stdin, closes inherited fds, then drives
 * pkgx_apt_txn_effect over the authenticated broker transport and prints the
 * outcome. It is NOT installed and it commits nothing without a real redeem_ok:
 * it needs root, the real broker socket, and a valid receipt on stdin, so it runs
 * only on a disposable VM. CI compiles+links it as the mutation-path proof.
 *
 *   make effect
 *   printf '{"effect_receipt":"...","correlation_id":"...","plan_schema":1,
 *           "packages":["nginx"],"lock_timeout":30}' \
 *     | sudo PKEXEC_UID=1000 ./pkgexec-effect apt.install     # VM only
 */
#include "../src/apt_effect.hh"
#include "../src/harden.h"
#include "../src/redeem.h"
#include "../src/request.h"
#include "../src/transport.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const char *status_name(pkgx_apt_status s) {
    switch (s) {
    case PKGX_APT_OK:
        return "ok";
    case PKGX_APT_NO_OP:
        return "no_op";
    case PKGX_APT_LOCKED:
        return "apt_locked";
    case PKGX_APT_NOT_OWNED:
        return "package_not_owned";
    case PKGX_APT_HELD:
        return "held";
    case PKGX_APT_PROTECTED:
        return "protected_package";
    case PKGX_APT_NO_INTENT:
        return "no_intent";
    case PKGX_APT_RESOLVE_FAILED:
        return "resolve_failed";
    case PKGX_APT_NOT_APPLIED:
        return "not_applied";
    case PKGX_APT_COMMIT_FAILED:
        return "operation_failed";
    case PKGX_APT_BROKEN:
        return "dpkg_broken";
    case PKGX_APT_INTERNAL:
        return "internal";
    }
    return "internal";
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: pkgexec-effect <apt.verb>  (request on stdin)\n");
        return 2;
    }
    const char *verb = argv[1];

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

    /* Hygiene before any dpkg/maintainer script runs — fail closed: a privileged
     * entrypoint must refuse if the environment cannot be scrubbed, stdin cannot
     * be neutralized, or inherited descriptors cannot be closed. */
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
    const char *detail = "";
    pkgx_apt_status st = pkgx_apt_txn_effect(
        verb, (const char *const *) req.packages, req.npackages,
        req.effect_receipt, uid, (int) req.plan_schema, req.correlation_id,
        (int) req.lock_timeout, &tx, out_cid, &detail);

    printf("status=%s detail=%s cid=%s\n", status_name(st), detail, out_cid);
    pkgx_request_free(&req);
    return (st == PKGX_APT_OK || st == PKGX_APT_NO_OP) ? 0 : 1;
}
