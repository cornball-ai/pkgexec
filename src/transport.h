/* Real broker transport (activation slice): AF_UNIX connect to the compiled-in
 * broker socket, SO_PEERCRED authentication of the peer BEFORE any byte is
 * written, one version-1 length-prefixed frame each way, and one ABSOLUTE
 * CLOCK_MONOTONIC deadline over the whole exchange (never reset by progress —
 * a stalling or trickling broker cannot pin a root helper open, mirroring the
 * broker's own anti-slowloris deadlines).
 *
 * The invariant pinned in runix docs/libapt-pkg-helper-plan.md (§Redeem): the
 * receipt token is never written to an unauthenticated peer. After connect()
 * and before the first write, the peer's kernel-verified credentials
 * (SO_PEERCRED — the uid of whoever bound/listens on the socket: the broker,
 * or systemd's activation listener) must equal required_peer_uid (0 in
 * production). Any other uid: close with zero bytes written.
 *
 * The transport never copies the request body (header and body are written
 * directly), so it holds no second copy of the token to wipe; the caller
 * (redeem.c) owns and wipes the request body. The reply body is not secret.
 *
 * Implements the pkgx_redeem_transport signature (redeem.h), so it drops into
 * pkgx_redeem in place of the test fakes. */
#ifndef PKGEXEC_TRANSPORT_H
#define PKGEXEC_TRANSPORT_H

#include <stddef.h>
#include <sys/types.h> /* uid_t */

#ifdef __cplusplus
extern "C" {
#endif

/* The broker's fixed socket (broker-owned process configuration — the systemd
 * unit's ListenStream — never caller-supplied) and its wire framing
 * (runix-audit-broker: [version:1][length:u32 big-endian][body]). */
#define PKGX_BROKER_SOCKET "/run/runix-audit.sock"
#define PKGX_FRAME_VERSION 1u
#define PKGX_FRAME_MAX_BODY 65536u
#define PKGX_TRANSPORT_TIMEOUT_MS 5000

typedef struct {
    const char *socket_path; /* PKGX_BROKER_SOCKET in production */
    uid_t required_peer_uid; /* 0 in production; the test server's uid in tests */
    int timeout_ms;          /* whole-exchange budget; <=0 -> the default */
    const char *err;         /* on failure: a static reason for diagnostics */
} pkgx_transport;

/* pkgx_redeem_transport-compatible; ctx is a pkgx_transport*. Returns 0 with a
 * malloc'd NUL-terminated reply body in *resp (*resplen bytes, caller frees),
 * else -1 with ctx->err set to one of: "request_size", "clock", "socket_path",
 * "socket", "connect", "deadline", "peer", "peer_uid", "send", "recv",
 * "frame_eof", "frame_version", "frame_toolarge", "oom". On "peer"/"peer_uid"
 * (and everything before them) zero request bytes have left the process. */
int pkgx_transport_tx(void *ctx, const char *req, size_t reqlen, char **resp,
                      size_t *resplen);

#ifdef __cplusplus
}
#endif

#endif /* PKGEXEC_TRANSPORT_H */
