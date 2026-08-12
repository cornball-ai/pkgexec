/* Schema-1 plan-digest encoder. See digest.h for the grammar. */
#include "digest.h"

#include <openssl/evp.h>
#include <stdlib.h>
#include <string.h>

/* ---- a growable byte buffer ------------------------------------------- */

typedef struct {
    unsigned char *p;
    size_t len, cap;
} buf;

static int buf_reserve(buf *b, size_t extra) {
    if (b->len + extra <= b->cap) {
        return 0;
    }
    size_t nc = b->cap ? b->cap : 64;
    while (nc < b->len + extra) {
        nc *= 2;
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

/* ---- helpers ---------------------------------------------------------- */

#define US 0x1f
#define RS 0x1e

/* A field value may not contain a separator (US/RS) or a sub-list delimiter
 * (',' '='). NULL is treated as the empty string (always safe). */
static int field_ok(const char *s) {
    if (s == NULL) {
        return 1;
    }
    for (const unsigned char *p = (const unsigned char *) s; *p != '\0'; p++) {
        if (*p == US || *p == RS || *p == ',' || *p == '=') {
            return 0;
        }
    }
    return 1;
}

static const char *nz(const char *s) { return s ? s : ""; }

/* Bytewise-ascending compare of two NUL-terminated strings (unsigned bytes,
 * shorter-first on a prefix), for qsort. */
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

/* Validate each item, sort a copy bytewise, and comma-join into a fresh string
 * ("" when n==0). Returns NULL on a delimiter violation or allocation failure.
 * *err is set to 1 only on a delimiter violation (a hard, fail-closed refusal),
 * so an empty-but-valid result is distinguishable from an error. */
static char *join_sorted(const char *const *items, size_t n, int *err) {
    *err = 0;
    for (size_t i = 0; i < n; i++) {
        if (!field_ok(items[i])) {
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
    buf b = {0};
    for (size_t i = 0; i < n; i++) {
        if ((i > 0 && buf_addc(&b, ',') != 0) ||
            buf_add(&b, tmp[i], strlen(tmp[i])) != 0) {
            free(tmp);
            free(b.p);
            return NULL;
        }
    }
    free(tmp);
    if (buf_addc(&b, '\0') != 0) {
        free(b.p);
        return NULL;
    }
    return (char *) b.p;
}

/* Render "k=v" pairs, sort those strings bytewise, comma-join. The fixed key
 * set has no prefix collisions, so a bytewise sort of the rendered pairs equals
 * a key sort. */
static char *join_sorted_kv(const char *const *keys, const char *const *vals,
                            size_t n, int *err) {
    *err = 0;
    char **pairs = calloc(n ? n : 1, sizeof *pairs);
    if (pairs == NULL) {
        return NULL;
    }
    for (size_t i = 0; i < n; i++) {
        if (!field_ok(keys[i]) || !field_ok(vals[i])) {
            *err = 1;
            for (size_t j = 0; j < i; j++) {
                free(pairs[j]);
            }
            free(pairs);
            return NULL;
        }
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

/* Append `s` to the record buffer as a field; caller writes the US separators. */
static int add_field(buf *b, const char *s) {
    if (!field_ok(s)) {
        return -1;
    }
    const char *v = nz(s);
    return buf_add(b, v, strlen(v));
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

/* Assemble "1" RS verb RS + (sorted recs joined by RS), hash it, and optionally
 * return the canonical bytes. Takes ownership of nothing; the caller frees recs. */
static int finalize(const char *verb, char **recs, size_t n,
                    char out_hex[65], unsigned char **canon, size_t *canon_len) {
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
    int err = 0;
    char *flags = join_sorted(r->flags, r->nflags, &err);
    if (flags == NULL) {
        return NULL; /* delimiter violation or OOM: fail closed */
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
    char **built = calloc(n ? n : 1, sizeof *built);
    if (built == NULL) {
        return -1;
    }
    for (size_t i = 0; i < n; i++) {
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
        char *comps = join_sorted(recs[i].components, recs[i].ncomponents, &err);
        if (comps == NULL) {
            free_recs(built, i);
            return -1;
        }
        char *opts = join_sorted_kv(recs[i].opt_keys, recs[i].opt_vals,
                                    recs[i].nopts, &err);
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
