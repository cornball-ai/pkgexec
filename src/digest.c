/* Schema-1 plan-digest encoder. See digest.h for the grammar. The encoder is
 * strict about the contract's DOMAIN, not just delimiters: it validates the
 * verb, the action/state/flag/option enums, refuses duplicate flags/option keys,
 * requires valid UTF-8, and bounds the canonical size (overflow-safe growth). An
 * out-of-domain value never produces an apparently-valid hash — it fails closed
 * (returns -1). */
#include "digest.h"

#include <openssl/evp.h>
#include <stdlib.h>
#include <string.h>

#define US 0x1f
#define RS 0x1e

/* ---- allowed domains (contract: broker-effect-receipt-contract.md) ---- */

static const char *const TXN_VERBS[] = {"apt.install", "apt.remove", "apt.purge",
                                        "apt.upgrade", "apt.dist_upgrade"};
static const char *const HOLD_VERBS[] = {"apt.hold", "apt.unhold"};
static const char *const ACTIONS[] = {"install", "upgrade", "downgrade",
                                      "remove", "purge"};
static const char *const FLAGS[] = {"hold", "auto", "essential", "protected"};
static const char *const CFG_STATES[] = {"half-installed", "unpacked",
                                         "half-configured", "triggers-awaited",
                                         "triggers-pending"};
static const char *const HOLD_STATES[] = {"hold", "install"};
static const char *const UPD_OPT_KEYS[] = {"signed-by", "architectures", "trusted"};

#define NELEM(a) (sizeof(a) / sizeof((a)[0]))

static int in_set(const char *s, const char *const *set, size_t n) {
    for (size_t i = 0; i < n; i++) {
        if (strcmp(s, set[i]) == 0) {
            return 1;
        }
    }
    return 0;
}

/* ---- a growable byte buffer, overflow-safe and size-bounded ----------- */

typedef struct {
    unsigned char *p;
    size_t len, cap;
} buf;

static int buf_reserve(buf *b, size_t extra) {
    /* Cap total size; this also prevents b->len + extra from overflowing, since
     * both operands are then bounded by PKGEXEC_DIGEST_MAX_CANON. */
    if (b->len > PKGEXEC_DIGEST_MAX_CANON ||
        extra > PKGEXEC_DIGEST_MAX_CANON - b->len) {
        return -1;
    }
    size_t need = b->len + extra;
    if (need <= b->cap) {
        return 0;
    }
    size_t nc = b->cap ? b->cap : 64;
    while (nc < need) {
        nc *= 2; /* bounded: need <= 4 MiB, so nc stays < SIZE_MAX/2 */
    }
    unsigned char *np = realloc(b->p, nc);
    if (np == NULL) {
        return -1;
    }
    b->p = np;
    b->cap = nc;
    return 0;
}

static int buf_add(buf *b, const void *d, size_t n) {
    if (buf_reserve(b, n) != 0) {
        return -1;
    }
    memcpy(b->p + b->len, d, n);
    b->len += n;
    return 0;
}

static int buf_addc(buf *b, unsigned char c) { return buf_add(b, &c, 1); }

/* ---- field helpers ---------------------------------------------------- */

static const char *nz(const char *s) { return s ? s : ""; }

/* Strict UTF-8 (rejects overlong forms, surrogates, and > U+10FFFF). */
static int utf8_valid(const char *s) {
    const unsigned char *p = (const unsigned char *) s;
    while (*p != '\0') {
        unsigned char c = *p;
        size_t n;
        unsigned int cp, min;
        if (c < 0x80) {
            p++;
            continue;
        } else if ((c & 0xE0) == 0xC0) {
            n = 1;
            min = 0x80;
            cp = c & 0x1F;
        } else if ((c & 0xF0) == 0xE0) {
            n = 2;
            min = 0x800;
            cp = c & 0x0F;
        } else if ((c & 0xF8) == 0xF0) {
            n = 3;
            min = 0x10000;
            cp = c & 0x07;
        } else {
            return 0;
        }
        for (size_t i = 0; i < n; i++) {
            p++;
            if ((*p & 0xC0) != 0x80) {
                return 0;
            }
            cp = (cp << 6) | (*p & 0x3F);
        }
        if (cp < min || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) {
            return 0;
        }
        p++;
    }
    return 1;
}

/* A field value may not contain a separator (US/RS) or a sub-list delimiter
 * (',' '='), and must be valid UTF-8. NULL is treated as the empty string. */
static int field_ok(const char *s) {
    if (s == NULL) {
        return 1;
    }
    for (const unsigned char *p = (const unsigned char *) s; *p != '\0'; p++) {
        if (*p == US || *p == RS || *p == ',' || *p == '=') {
            return 0;
        }
    }
    return utf8_valid(s);
}

static int cmp_bytewise(const void *a, const void *b) {
    const unsigned char *x = *(const unsigned char *const *) a;
    const unsigned char *y = *(const unsigned char *const *) b;
    while (*x != '\0' && *y != '\0') {
        if (*x != *y) {
            return (int) *x - (int) *y;
        }
        x++;
        y++;
    }
    return (int) *x - (int) *y;
}

static int sha256_hex(const unsigned char *data, size_t n, char out[65]) {
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int mdlen = 0;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        return -1;
    }
    int ok = EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1 &&
             EVP_DigestUpdate(ctx, data, n) == 1 &&
             EVP_DigestFinal_ex(ctx, md, &mdlen) == 1 && mdlen == 32;
    EVP_MD_CTX_free(ctx);
    if (!ok) {
        return -1;
    }
    static const char hx[] = "0123456789abcdef";
    for (int i = 0; i < 32; i++) {
        out[2 * i] = hx[md[i] >> 4];
        out[2 * i + 1] = hx[md[i] & 0xf];
    }
    out[64] = '\0';
    return 0;
}

/* Validate each item (delimiter/UTF-8, and against `allowed` if non-NULL), sort
 * a copy bytewise, optionally refuse a duplicate, and comma-join. Returns NULL
 * on a violation (with *err=1) or allocation failure (*err=0). */
static char *join_sorted(const char *const *items, size_t n, int dedup,
                         const char *const *allowed, size_t nallowed, int *err) {
    *err = 0;
    for (size_t i = 0; i < n; i++) {
        if (!field_ok(items[i]) ||
            (allowed != NULL && !in_set(nz(items[i]), allowed, nallowed))) {
            *err = 1;
            return NULL;
        }
    }
    const char **tmp = calloc(n ? n : 1, sizeof *tmp);
    if (tmp == NULL) {
        return NULL;
    }
    for (size_t i = 0; i < n; i++) {
        tmp[i] = nz(items[i]);
    }
    qsort(tmp, n, sizeof *tmp, cmp_bytewise);
    if (dedup) {
        for (size_t i = 1; i < n; i++) {
            if (strcmp(tmp[i - 1], tmp[i]) == 0) {
                *err = 1;
                free(tmp);
                return NULL;
            }
        }
    }
    buf b = {0};
    int fail = 0;
    for (size_t i = 0; i < n; i++) {
        if ((i > 0 && buf_addc(&b, ',') != 0) ||
            buf_add(&b, tmp[i], strlen(tmp[i])) != 0) {
            fail = 1;
            break;
        }
    }
    free(tmp);
    if (fail || buf_addc(&b, '\0') != 0) {
        free(b.p);
        return NULL;
    }
    return (char *) b.p;
}

/* Render "k=v" pairs (keys validated against `allowed`, duplicate keys refused),
 * sort bytewise, comma-join. */
static char *join_sorted_kv(const char *const *keys, const char *const *vals,
                            size_t n, const char *const *allowed, size_t nallowed,
                            int *err) {
    *err = 0;
    for (size_t i = 0; i < n; i++) {
        if (!field_ok(keys[i]) || !field_ok(vals[i]) ||
            !in_set(nz(keys[i]), allowed, nallowed)) {
            *err = 1;
            return NULL;
        }
        for (size_t j = 0; j < i; j++) {
            if (strcmp(nz(keys[i]), nz(keys[j])) == 0) { /* duplicate key */
                *err = 1;
                return NULL;
            }
        }
    }
    char **pairs = calloc(n ? n : 1, sizeof *pairs);
    if (pairs == NULL) {
        return NULL;
    }
    for (size_t i = 0; i < n; i++) {
        const char *k = nz(keys[i]), *v = nz(vals[i]);
        size_t kl = strlen(k), vl = strlen(v);
        char *kv = malloc(kl + 1 + vl + 1);
        if (kv == NULL) {
            for (size_t j = 0; j < i; j++) {
                free(pairs[j]);
            }
            free(pairs);
            return NULL;
        }
        memcpy(kv, k, kl);
        kv[kl] = '=';
        memcpy(kv + kl + 1, v, vl);
        kv[kl + 1 + vl] = '\0';
        pairs[i] = kv;
    }
    qsort(pairs, n, sizeof *pairs, cmp_bytewise);
    buf b = {0};
    int fail = 0;
    for (size_t i = 0; i < n; i++) {
        if ((i > 0 && buf_addc(&b, ',') != 0) ||
            buf_add(&b, pairs[i], strlen(pairs[i])) != 0) {
            fail = 1;
            break;
        }
    }
    for (size_t i = 0; i < n; i++) {
        free(pairs[i]);
    }
    free(pairs);
    if (fail || buf_addc(&b, '\0') != 0) {
        free(b.p);
        return NULL;
    }
    return (char *) b.p;
}

static int add_field(buf *b, const char *s) {
    if (!field_ok(s)) {
        return -1;
    }
    const char *v = nz(s);
    return buf_add(b, v, strlen(v));
}

/* Assemble "1" RS verb RS + (sorted recs joined by RS), hash it, optionally
 * return the canonical bytes. The caller frees recs. */
static int finalize(const char *verb, char **recs, size_t n, char out_hex[65],
                    unsigned char **canon, size_t *canon_len) {
    if (!field_ok(verb)) {
        return -1;
    }
    qsort(recs, n, sizeof *recs, cmp_bytewise);
    buf b = {0};
    int fail = buf_addc(&b, '1') != 0 || buf_addc(&b, RS) != 0 ||
               buf_add(&b, verb, strlen(verb)) != 0 || buf_addc(&b, RS) != 0;
    for (size_t i = 0; !fail && i < n; i++) {
        fail = (i > 0 && buf_addc(&b, RS) != 0) ||
               buf_add(&b, recs[i], strlen(recs[i])) != 0;
    }
    if (fail) {
        free(b.p);
        return -1;
    }
    char hex[65];
    if (sha256_hex(b.p, b.len, hex) != 0) {
        free(b.p);
        return -1;
    }
    memcpy(out_hex, hex, 65);
    if (canon != NULL) {
        *canon = b.p;
        *canon_len = b.len;
    } else {
        free(b.p);
    }
    return 0;
}

static void free_recs(char **recs, size_t n) {
    for (size_t i = 0; i < n; i++) {
        free(recs[i]);
    }
    free(recs);
}

/* ---- per-verb encoders ------------------------------------------------ */

static char *pkg_txn_record(const pkgx_txn_record *r) {
    if (!in_set(nz(r->action), ACTIONS, NELEM(ACTIONS))) {
        return NULL; /* out-of-domain action: fail closed */
    }
    int err = 0;
    char *flags = join_sorted(r->flags, r->nflags, 1, FLAGS, NELEM(FLAGS), &err);
    if (flags == NULL) {
        return NULL;
    }
    buf b = {0};
    int fail = add_field(&b, r->package) != 0 || buf_addc(&b, US) != 0 ||
               add_field(&b, r->architecture) != 0 || buf_addc(&b, US) != 0 ||
               add_field(&b, r->action) != 0 || buf_addc(&b, US) != 0 ||
               add_field(&b, r->from_version) != 0 || buf_addc(&b, US) != 0 ||
               add_field(&b, r->to_version) != 0 || buf_addc(&b, US) != 0 ||
               buf_add(&b, flags, strlen(flags)) != 0 || buf_addc(&b, '\0') != 0;
    free(flags);
    if (fail) {
        free(b.p);
        return NULL;
    }
    return (char *) b.p;
}

int pkgx_digest_pkg_txn(const char *verb, const pkgx_txn_record *recs, size_t n,
                        char out_hex[65], unsigned char **canon, size_t *canon_len) {
    if (verb == NULL || !in_set(verb, TXN_VERBS, NELEM(TXN_VERBS))) {
        return -1;
    }
    char **built = calloc(n ? n : 1, sizeof *built);
    if (built == NULL) {
        return -1;
    }
    for (size_t i = 0; i < n; i++) {
        built[i] = pkg_txn_record(&recs[i]);
        if (built[i] == NULL) {
            free_recs(built, i);
            return -1;
        }
    }
    int rc = finalize(verb, built, n, out_hex, canon, canon_len);
    free_recs(built, n);
    return rc;
}

int pkgx_digest_configure(const pkgx_cfg_record *recs, size_t n, char out_hex[65],
                          unsigned char **canon, size_t *canon_len) {
    char **built = calloc(n ? n : 1, sizeof *built);
    if (built == NULL) {
        return -1;
    }
    for (size_t i = 0; i < n; i++) {
        if (!in_set(nz(recs[i].state), CFG_STATES, NELEM(CFG_STATES))) {
            free_recs(built, i);
            return -1;
        }
        buf b = {0};
        int fail = add_field(&b, recs[i].package) != 0 || buf_addc(&b, US) != 0 ||
                   add_field(&b, recs[i].architecture) != 0 || buf_addc(&b, US) != 0 ||
                   add_field(&b, recs[i].current_version) != 0 || buf_addc(&b, US) != 0 ||
                   add_field(&b, recs[i].state) != 0 || buf_addc(&b, '\0') != 0;
        if (fail) {
            free(b.p);
            free_recs(built, i);
            return -1;
        }
        built[i] = (char *) b.p;
    }
    int rc = finalize("apt.configure", built, n, out_hex, canon, canon_len);
    free_recs(built, n);
    return rc;
}

int pkgx_digest_hold(const char *verb, const pkgx_hold_record *recs, size_t n,
                     char out_hex[65], unsigned char **canon, size_t *canon_len) {
    if (verb == NULL || !in_set(verb, HOLD_VERBS, NELEM(HOLD_VERBS))) {
        return -1;
    }
    char **built = calloc(n ? n : 1, sizeof *built);
    if (built == NULL) {
        return -1;
    }
    for (size_t i = 0; i < n; i++) {
        if (!in_set(nz(recs[i].from_state), HOLD_STATES, NELEM(HOLD_STATES)) ||
            !in_set(nz(recs[i].to_state), HOLD_STATES, NELEM(HOLD_STATES))) {
            free_recs(built, i);
            return -1;
        }
        buf b = {0};
        int fail = add_field(&b, recs[i].package) != 0 || buf_addc(&b, US) != 0 ||
                   add_field(&b, recs[i].from_state) != 0 || buf_addc(&b, US) != 0 ||
                   add_field(&b, recs[i].to_state) != 0 || buf_addc(&b, '\0') != 0;
        if (fail) {
            free(b.p);
            free_recs(built, i);
            return -1;
        }
        built[i] = (char *) b.p;
    }
    int rc = finalize(verb, built, n, out_hex, canon, canon_len);
    free_recs(built, n);
    return rc;
}

int pkgx_digest_update(const pkgx_src_record *recs, size_t n, char out_hex[65],
                       unsigned char **canon, size_t *canon_len) {
    char **built = calloc(n ? n : 1, sizeof *built);
    if (built == NULL) {
        return -1;
    }
    for (size_t i = 0; i < n; i++) {
        int err = 0;
        char *comps = join_sorted(recs[i].components, recs[i].ncomponents, 1, NULL,
                                  0, &err);
        if (comps == NULL) {
            free_recs(built, i);
            return -1;
        }
        char *opts = join_sorted_kv(recs[i].opt_keys, recs[i].opt_vals,
                                    recs[i].nopts, UPD_OPT_KEYS,
                                    NELEM(UPD_OPT_KEYS), &err);
        if (opts == NULL) {
            free(comps);
            free_recs(built, i);
            return -1;
        }
        buf b = {0};
        int fail = add_field(&b, recs[i].uri) != 0 || buf_addc(&b, US) != 0 ||
                   add_field(&b, recs[i].suite) != 0 || buf_addc(&b, US) != 0 ||
                   buf_add(&b, comps, strlen(comps)) != 0 || buf_addc(&b, US) != 0 ||
                   buf_add(&b, opts, strlen(opts)) != 0 || buf_addc(&b, '\0') != 0;
        free(comps);
        free(opts);
        if (fail) {
            free(b.p);
            free_recs(built, i);
            return -1;
        }
        built[i] = (char *) b.p;
    }
    int rc = finalize("apt.update", built, n, out_hex, canon, canon_len);
    free_recs(built, n);
    return rc;
}

int pkgx_resource(const char *const *targets, size_t n, char **out) {
    int err = 0;
    char *j = join_sorted(targets, n, 1 /* refuse duplicates */, NULL, 0, &err);
    if (j == NULL) {
        return -1;
    }
    *out = j;
    return 0;
}
