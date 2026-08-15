/* Schema-1 plan digest: the canonical byte encoding of an apt plan and its
 * SHA-256, computed with OpenSSL EVP. Deliberately independent of libapt — the
 * caller (the R preview at issue, or the helper's atomic libapt resolve at
 * redeem) fills the typed per-verb records below; this module owns the byte
 * grammar so both sides produce identical bytes for the same plan.
 *
 * Grammar (broker-effect-receipt-contract.md, "Plan digest"): SHA-256 over
 * "1" RS verb RS then the records joined by RS; each record is its per-verb
 * fields joined by US; records are sorted bytewise ascending; flags/components/
 * options within a record are bytewise-sorted comma (and k=v) lists. US=0x1f,
 * RS=0x1e. No field value may contain US, RS, ',' or '=' — a value that does is
 * a fail-closed refusal (return -1), never escaped or truncated. */
#ifndef PKGEXEC_DIGEST_H
#define PKGEXEC_DIGEST_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PKGEXEC_PLAN_SCHEMA_V1 1
#define PKGEXEC_DIGEST_HEX 64 /* lowercase hex SHA-256; +1 for the NUL */

/* Hard cap on the canonical byte string, so buffer growth is overflow-safe and
 * a pathological plan cannot exhaust memory. Real plans are far smaller. */
#define PKGEXEC_DIGEST_MAX_CANON (4u * 1024u * 1024u)

/* install/remove/purge/upgrade/dist_upgrade, over the whole resolved
 * transaction. NULL string fields are treated as empty. `flags` is drawn from
 * {hold,auto,essential,protected}; the encoder sorts and comma-joins them. */
typedef struct {
    const char *package, *architecture, *action, *from_version, *to_version;
    const char *const *flags;
    size_t nflags;
} pkgx_txn_record;

/* apt.configure: the pending-configuration set. */
typedef struct {
    const char *package, *architecture, *current_version, *state;
} pkgx_cfg_record;

/* apt.hold / apt.unhold: the selection-state change. */
typedef struct {
    const char *package, *from_state, *to_state;
} pkgx_hold_record;

/* apt.update: the configured source set. `components` is sorted+comma-joined;
 * `opt_keys`/`opt_vals` are the identity-relevant options, rendered "k=v",
 * sorted bytewise, comma-joined. */
typedef struct {
    const char *uri, *suite;
    const char *const *components;
    size_t ncomponents;
    const char *const *opt_keys, *const *opt_vals;
    size_t nopts;
} pkgx_src_record;

/* Each writes a 64-char lowercase-hex SHA-256 (NUL-terminated) to out_hex, and
 * returns 0. On any delimiter-safety violation or allocation failure it returns
 * -1 and out_hex is untouched (fail-closed). If `canon` is non-NULL the
 * canonical byte string is also returned in a freshly malloc'd buffer (caller
 * frees) with its length in *canon_len — for golden byte comparison. `verb` is
 * the operation string, e.g. "apt.install". */
int pkgx_digest_pkg_txn(const char *verb, const pkgx_txn_record *recs, size_t n,
                        char out_hex[PKGEXEC_DIGEST_HEX + 1],
                        unsigned char **canon, size_t *canon_len);
int pkgx_digest_configure(const pkgx_cfg_record *recs, size_t n,
                          char out_hex[PKGEXEC_DIGEST_HEX + 1],
                          unsigned char **canon, size_t *canon_len);
int pkgx_digest_hold(const char *verb, const pkgx_hold_record *recs, size_t n,
                     char out_hex[PKGEXEC_DIGEST_HEX + 1], unsigned char **canon,
                     size_t *canon_len);
int pkgx_digest_update(const pkgx_src_record *recs, size_t n,
                       char out_hex[PKGEXEC_DIGEST_HEX + 1], unsigned char **canon,
                       size_t *canon_len);

/* Canonical `resource` for a target-name request: the requested target names,
 * bytewise-sorted, comma-joined, delimiter/UTF-8-validated, duplicates refused.
 * The same rule the future R issue side must use, so issue and redeem agree.
 * Returns 0 and a malloc'd string (caller frees; "" when n==0), or -1. The
 * fixed-token resources (update = "", configure = "pending") are chosen by the
 * caller, not this function. */
int pkgx_resource(const char *const *targets, size_t n, char **out);

/* Lowercase-hex SHA-256 of `n` bytes into out_hex (64 hex + NUL); 0 or -1.
 * Exposed for schema-1 field normalization (pkgx_signed_by_inline_token). */
int pkgx_sha256_hex(const unsigned char *data, size_t n,
                    char out_hex[PKGEXEC_DIGEST_HEX + 1]);

/* strlen("inline-sha256:") + 64 hex. The fixed length of the inline-key token. */
#define PKGX_SIGNEDBY_TOKEN_LEN 78

/* Schema-1 normalization of a source record's `signed-by` value for digesting
 * (broker-effect-receipt-contract.md, "Plan digest"). libapt-pkg returns either a
 * keyring path / fingerprint (field-safe) or an inline armored public key
 * (multi-line, carrying '=' and newlines the field grammar forbids). If `value`
 * (of length `len`) is libapt-pkg's valid inline armored-key form
 * (`-----BEGIN PGP PUBLIC KEY BLOCK----- ... -----END PGP PUBLIC KEY BLOCK-----`,
 * only trailing whitespace after the footer), write the stable token
 * "inline-sha256:<64 lowercase hex>" of the EXACT `len` bytes to `token` and
 * return 1. Otherwise leave `token` untouched and return 0 (the caller keeps the
 * original value; a non-field-safe original still fails closed at digest, so an
 * arbitrary reserved-byte value is never hashed away). Return -1 on hash failure.
 * `token` must hold PKGX_SIGNEDBY_TOKEN_LEN + 1 bytes. */
int pkgx_signed_by_inline_token(const char *value, size_t len,
                                char token[PKGX_SIGNEDBY_TOKEN_LEN + 1]);

#ifdef __cplusplus
}
#endif

#endif /* PKGEXEC_DIGEST_H */
