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

#ifdef __cplusplus
}
#endif

#endif /* PKGEXEC_RESULT_H */
