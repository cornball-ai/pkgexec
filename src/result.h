/* The helper's result channel: the single strict JSON object a per-verb
 * entrypoint writes to stdout, which the R caller parses to reconstruct the
 * outcome (plan §5). The status maps to a stable runix_* condition name, and
 * `effect_issued` is carried as a FIRST-CLASS boolean — the honest answer to "was
 * the host possibly mutated?" — never inferred from the status or from the fact a
 * receipt was redeemed. Pure (Jansson only), so it is unit-tested without root. */
#ifndef PKGEXEC_RESULT_H
#define PKGEXEC_RESULT_H

#include "apt_status.h"

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* The runix_* condition name for a status (plan §5). Stable, lowercase; the R
 * caller matches on these exact strings. Total over the enum. */
const char *pkgx_status_name(pkgx_apt_status st);

/* Serialize the result channel as one strict, compact JSON object into `out`
 * (caller buffer of `outlen`), NUL-terminated:
 *   {"status":"...","effect_issued":true|false,"correlation_id":"...","detail":"..."}
 * `effect_issued` is emitted as a JSON boolean, independent of `st`. NULL
 * correlation_id/detail serialize as "". Returns the byte count written (excluding
 * the NUL), or -1 if `out` is too small or a field is not encodable (fail-closed:
 * `out` is left untouched on -1). */
int pkgx_result_json(pkgx_apt_status st, int effect_issued,
                     const char *correlation_id, const char *detail, char *out,
                     size_t outlen);

/* Serialize the result and write it in full — the JSON object then a newline — to
 * `fd`. SIGPIPE is ignored for the write, so a result pipe the caller already
 * closed yields a reported failure rather than killing the process. Returns 0 only
 * when the entire record was written; -1 if serialization failed or the write did
 * not complete (a closed or short result channel must never read as success).
 * Failing to emit this record is the ONLY thing a helper reports out-of-band. */
int pkgx_result_emit(int fd, pkgx_apt_status st, int effect_issued,
                     const char *correlation_id, const char *detail);

/* Isolate the result channel BEFORE any effector runs. dup the current stdout to a
 * fresh close-on-exec fd — the ONLY fd the strict JSON result is ever written to —
 * then point stdout (fd 1) at stderr, so anything an effector, the libapt commit, or
 * a spawned dpkg writes to fd 1 lands on stderr and never pollutes the protocol
 * channel. The dedicated fd is CLOEXEC (a spawned child cannot inherit it), and
 * stdout is NEVER restored. Returns the dedicated result fd (>= 0), or -1 on failure
 * (fail closed: the caller must exit without emitting a result). */
int pkgx_result_channel_open(void);

/* The detail field's fixed capacity. Effectors write detail into a caller-owned
 * buffer of this size with pkgx_detail_set — never a pointer borrowed from
 * transient libapt storage (a resolved-transaction deque, a package name held in
 * the cache) that is destroyed when the effector returns. A borrowed detail read
 * back by the entrypoint after that return is a dangling read that corrupts the
 * result JSON (observed as a garbled/unknown status); the copy keeps it valid.
 * Sized to hold any package name or status tag; a longer string is truncated (the
 * detail is diagnostic, the status is the decision). */
#define PKGX_DETAIL_CAP 128

/* Copy `s` (NULL treated as "") into `detail`, a caller buffer of PKGX_DETAIL_CAP
 * bytes, truncating to fit and always NUL-terminating. A no-op if detail is NULL. */
void pkgx_detail_set(char *detail, const char *s);

#ifdef __cplusplus
}
#endif

#endif /* PKGEXEC_RESULT_H */
