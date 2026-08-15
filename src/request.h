/* Strict parsing of the helper's stdin request. Slice 1 is deliberately
 * incapable of mutation: this parses and validates the request an entrypoint
 * receives on fd 0 (the receipt token, the correlation id, the plan schema, the
 * target packages, the lock timeout) and nothing else. The verb is NOT read
 * from the request — it is the entrypoint's own compile-time constant, passed
 * in, so a caller can never select the verb through input.
 *
 * Parsing uses system Jansson with JSON_REJECT_DUPLICATES and no
 * JSON_DISABLE_EOF_CHECK (complete-input, UTF-8 enforced). All bounds below are
 * enforced before or during parse; a breach is a typed refusal, never a
 * best-effort parse. */
#ifndef PKGEXEC_REQUEST_H
#define PKGEXEC_REQUEST_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PKGX_RECEIPT_HEXLEN 32   /* the 128-bit token as 32 lowercase hex */
#define PKGX_CID_MAX 64
#define PKGX_MAX_STDIN 65536     /* hard cap on the request bytes (64 KiB) */
#define PKGX_MAX_PACKAGES 256
#define PKGX_MAX_NAME 256
#define PKGX_MAX_DEPTH 4         /* the request is shallow */
#define PKGX_LOCK_TIMEOUT_MAX 3600
#define PKGX_STDIN_DEADLINE_SEC 5 /* absolute read deadline, anti-slowloris */
#define PKGX_VERB_MAX 32          /* longest apt.* verb is 16 bytes; ample */

typedef struct {
    char effect_receipt[PKGX_RECEIPT_HEXLEN + 1];
    char correlation_id[PKGX_CID_MAX + 1];
    long plan_schema;
    char **packages; /* malloc'd array of malloc'd, validated names */
    size_t npackages;
    long lock_timeout;
} pkgx_request;

/* Read the request from `fd` with a hard byte cap (PKGX_MAX_STDIN) and an
 * absolute wall-clock deadline (PKGX_STDIN_DEADLINE_SEC). Returns 0 with a
 * malloc'd NUL-terminated buffer (caller frees) and its length, or -1 with
 * *errcode set to "too_large", "deadline", or "io". */
int pkgx_read_stdin(int fd, char **body, size_t *len, const char **errcode);

/* As pkgx_read_stdin, with an explicit deadline in milliseconds — a test seam so
 * the deadline can be exercised without adding real seconds to a run. */
int pkgx_read_stdin_deadline(int fd, char **body, size_t *len,
                             const char **errcode, long deadline_ms);

/* Wipe `n` bytes at `p` so a secret (the raw request body carrying the receipt)
 * does not linger in freed memory. A no-op on NULL. */
void pkgx_secure_wipe(void *p, size_t n);

/* The broker correlation-id grammar: exactly 20 digits, '-', 16 lowercase hex.
 * Exposed so the commit gate can revalidate a cid before it commits under it,
 * reusing this one definition rather than trusting an upstream check. Returns 1
 * if `s` matches, 0 otherwise (including NULL). */
int pkgx_cid_valid(const char *s);

/* Parse+validate `body` for `verb` (the entrypoint's compile-time verb, one of
 * the nine apt.* strings). Strict: rejects duplicate keys, trailing content,
 * unknown members, missing members, depth > PKGX_MAX_DEPTH, a receipt that is
 * not exactly 32 lowercase hex, a malformed correlation id, plan_schema != 1, a
 * lock_timeout outside [0, PKGX_LOCK_TIMEOUT_MAX], a package list over
 * PKGX_MAX_PACKAGES, a name failing the strict pattern, and per-verb package
 * arity. Returns 0 and fills *out (free with pkgx_request_free), or -1 with
 * *errcode ("schema_invalid", "bad_json", "unknown_request"). */
int pkgx_parse_request(const char *verb, const char *body, size_t len,
                       pkgx_request *out, const char **errcode);

void pkgx_request_free(pkgx_request *req);

/* The unprivileged read-only preview (runix-apt-preview) request: a distinct,
 * receipt-free shape carrying only the plan inputs. The verb IS read from the
 * request here (there is no compile-time entrypoint binding to protect — the
 * preview commits nothing), but it is validated against the same nine-verb
 * allowlist and arity as an effector request. */
typedef struct {
    char verb[PKGX_VERB_MAX];
    char **packages; /* malloc'd array of malloc'd, validated names */
    size_t npackages;
} pkgx_preview_request;

/* Parse+validate `body` as the three-key preview request
 * {"schema_version":1,"verb":"apt.*","packages":[...]}. Strict with the SAME
 * rules pkgx_parse_request enforces — rejects duplicate keys, trailing content,
 * unknown members, missing members, depth > PKGX_MAX_DEPTH, bad UTF-8,
 * schema_version != 1, an unknown verb, a package list over PKGX_MAX_PACKAGES, a
 * name failing the strict pattern, a duplicate name, and per-verb arity. Returns
 * 0 and fills *out (free with pkgx_preview_request_free), or -1 with *errcode
 * ("bad_json", "schema_invalid", "unknown_request"). */
int pkgx_parse_preview_request(const char *body, size_t len,
                               pkgx_preview_request *out, const char **errcode);

void pkgx_preview_request_free(pkgx_preview_request *req);

#ifdef __cplusplus
}
#endif

#endif /* PKGEXEC_REQUEST_H */
