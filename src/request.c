/* Strict stdin-request parsing. See request.h. */
#include "request.h"

#include <errno.h>
#include <jansson.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* ---- grammar helpers -------------------------------------------------- */

static int is_lc_hex(const char *s, size_t n) {
    if (strlen(s) != n) {
        return 0;
    }
    for (size_t i = 0; i < n; i++) {
        char c = s[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
            return 0;
        }
    }
    return 1;
}

/* Broker correlation id: exactly 20 digits, '-', 16 lowercase hex. */
int pkgx_cid_valid(const char *s) {
    if (s == NULL || strlen(s) != 20 + 1 + 16) {
        return 0;
    }
    for (int i = 0; i < 20; i++) {
        if (s[i] < '0' || s[i] > '9') {
            return 0;
        }
    }
    if (s[20] != '-') {
        return 0;
    }
    for (int i = 21; i < 37; i++) {
        char c = s[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
            return 0;
        }
    }
    return 1;
}

/* Strict apt package name, optionally arch-qualified: a Debian package name
 * ([a-z0-9] then [a-z0-9+.-], >= 2 chars) with an optional ":<arch>" suffix,
 * where the arch is [a-z0-9] then [a-z0-9-] (no leading '-'). */
static int name_ok(const char *s) {
    size_t n = strlen(s);
    if (n < 2 || n > PKGX_MAX_NAME) {
        return 0;
    }
    const char *colon = strchr(s, ':');
    size_t namelen = colon ? (size_t) (colon - s) : n;
    if (namelen < 2) {
        return 0;
    }
    for (size_t i = 0; i < namelen; i++) {
        char c = s[i];
        int first = (i == 0);
        int ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
                 (!first && (c == '+' || c == '.' || c == '-'));
        if (!ok) {
            return 0;
        }
    }
    if (colon) {
        const char *arch = colon + 1;
        if (*arch == '\0') {
            return 0;
        }
        for (const char *p = arch; *p; p++) {
            char c = *p;
            int first = (p == arch);
            int ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
                     (!first && c == '-'); /* no leading '-' in the arch */
            if (!ok) {
                return 0;
            }
        }
    }
    return 1;
}

/* A JSON string carrying no embedded NUL. An escaped NUL makes Jansson's
 * reported byte length exceed the C-string length; reject that. Returns the
 * value, or NULL. */
static const char *str_clean(json_t *v) {
    if (!json_is_string(v)) {
        return NULL;
    }
    const char *s = json_string_value(v);
    if (strlen(s) != json_string_length(v)) {
        return NULL;
    }
    return s;
}

static int depth(const json_t *v) {
    if (json_is_object(v)) {
        int m = 0;
        const char *k;
        json_t *e;
        json_object_foreach((json_t *) v, k, e) {
            int d = depth(e);
            if (d > m) {
                m = d;
            }
        }
        return m + 1;
    }
    if (json_is_array(v)) {
        int m = 0;
        size_t i;
        json_t *e;
        json_array_foreach(v, i, e) {
            int d = depth(e);
            if (d > m) {
                m = d;
            }
        }
        return m + 1;
    }
    return 0;
}

enum { ARITY_NONE, ARITY_ONE_PLUS };
static int verb_arity(const char *verb) {
    /* update/configure take no packages; upgrade/dist_upgrade are whole-system
     * in v1 (target-scoped upgrades are not yet implemented, so targets are
     * rejected rather than silently ignored). */
    if (strcmp(verb, "apt.update") == 0 || strcmp(verb, "apt.configure") == 0 ||
        strcmp(verb, "apt.upgrade") == 0 || strcmp(verb, "apt.dist_upgrade") == 0) {
        return ARITY_NONE;
    }
    if (strcmp(verb, "apt.install") == 0 || strcmp(verb, "apt.remove") == 0 ||
        strcmp(verb, "apt.purge") == 0 || strcmp(verb, "apt.hold") == 0 ||
        strcmp(verb, "apt.unhold") == 0) {
        return ARITY_ONE_PLUS;
    }
    return -1;
}

/* ---- stdin read with cap + deadline ---------------------------------- */

void pkgx_secure_wipe(void *p, size_t n) {
    if (p != NULL) {
        explicit_bzero(p, n);
    }
}

int pkgx_read_stdin_deadline(int fd, char **body, size_t *len,
                             const char **errcode, long deadline_ms) {
    struct timespec start;
    if (clock_gettime(CLOCK_MONOTONIC, &start) != 0) {
        *errcode = "io";
        return -1;
    }
    size_t cap = 4096, n = 0;
    char *buf = malloc(cap + 1);
    if (buf == NULL) {
        *errcode = "io";
        return -1;
    }
    /* Every failure below jumps to `fail`, which wipes the partial buffer before
     * freeing it: a partial read can already hold the effect-receipt token, so a
     * timeout / I/O / allocation / oversize error must never leak it to freed
     * heap. Only a clean EOF reaches the success return with an intact buffer. */
    for (;;) {
        struct timespec now;
        if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
            *errcode = "io";
            goto fail;
        }
        long elapsed = (now.tv_sec - start.tv_sec) * 1000 +
                       (now.tv_nsec - start.tv_nsec) / 1000000;
        long remaining = deadline_ms - elapsed;
        if (remaining <= 0) {
            *errcode = "deadline";
            goto fail;
        }
        struct pollfd pfd = {.fd = fd, .events = POLLIN};
        int pr = poll(&pfd, 1, (int) remaining);
        if (pr < 0) {
            if (errno == EINTR) {
                continue;
            }
            *errcode = "io";
            goto fail;
        }
        if (pr == 0) {
            *errcode = "deadline";
            goto fail;
        }
        if (n == cap) {
            size_t nc = cap * 2;
            if (nc > PKGX_MAX_STDIN + 1) {
                nc = PKGX_MAX_STDIN + 1;
            }
            char *nb = realloc(buf, nc + 1);
            if (nb == NULL) {
                *errcode = "io"; /* buf still valid; wiped at fail */
                goto fail;
            }
            buf = nb;
            cap = nc;
        }
        ssize_t r = read(fd, buf + n, cap - n);
        if (r < 0) {
            if (errno == EINTR) {
                continue;
            }
            *errcode = "io";
            goto fail;
        }
        if (r == 0) {
            break; /* EOF */
        }
        n += (size_t) r;
        if (n > PKGX_MAX_STDIN) {
            *errcode = "too_large";
            goto fail;
        }
    }
    buf[n] = '\0';
    *body = buf;
    *len = n;
    return 0;
fail:
    pkgx_secure_wipe(buf, n); /* n bytes read so far may contain the receipt */
    free(buf);
    return -1;
}

int pkgx_read_stdin(int fd, char **body, size_t *len, const char **errcode) {
    return pkgx_read_stdin_deadline(fd, body, len, errcode,
                                    (long) PKGX_STDIN_DEADLINE_SEC * 1000);
}

/* ---- parse ------------------------------------------------------------ */

static const char *ALLOWED[] = {"effect_receipt", "correlation_id",
                                "plan_schema", "packages", "lock_timeout"};

static int is_allowed_key(const char *k) {
    for (size_t i = 0; i < sizeof ALLOWED / sizeof *ALLOWED; i++) {
        if (strcmp(k, ALLOWED[i]) == 0) {
            return 1;
        }
    }
    return 0;
}

int pkgx_parse_request(const char *verb, const char *body, size_t len,
                       pkgx_request *out, const char **errcode) {
    memset(out, 0, sizeof *out);
    int arity = verb_arity(verb);
    if (arity < 0) {
        *errcode = "unknown_request";
        return -1;
    }
    json_error_t err;
    json_t *root = json_loadb(body, len, JSON_REJECT_DUPLICATES, &err);
    if (root == NULL) {
        *errcode = "bad_json";
        return -1;
    }
    const char *ec = "schema_invalid";
    if (!json_is_object(root) || depth(root) > PKGX_MAX_DEPTH) {
        goto fail;
    }
    {
        const char *k;
        json_t *v;
        json_object_foreach(root, k, v) {
            if (!is_allowed_key(k)) {
                goto fail;
            }
        }
    }

    const char *rcpt = str_clean(json_object_get(root, "effect_receipt"));
    if (rcpt == NULL || !is_lc_hex(rcpt, PKGX_RECEIPT_HEXLEN)) {
        goto fail;
    }
    memcpy(out->effect_receipt, rcpt, PKGX_RECEIPT_HEXLEN + 1);

    const char *cid = str_clean(json_object_get(root, "correlation_id"));
    if (cid == NULL || !pkgx_cid_valid(cid)) {
        goto fail;
    }
    strcpy(out->correlation_id, cid);

    json_t *jp = json_object_get(root, "plan_schema");
    if (!json_is_integer(jp) || json_integer_value(jp) != 1) {
        goto fail;
    }
    out->plan_schema = 1;

    json_t *jt = json_object_get(root, "lock_timeout");
    if (!json_is_integer(jt)) {
        goto fail;
    }
    json_int_t t = json_integer_value(jt);
    if (t < 0 || t > PKGX_LOCK_TIMEOUT_MAX) {
        goto fail;
    }
    out->lock_timeout = (long) t;

    json_t *jpk = json_object_get(root, "packages");
    if (!json_is_array(jpk)) {
        goto fail;
    }
    size_t np = json_array_size(jpk);
    if (np > PKGX_MAX_PACKAGES) {
        goto fail;
    }
    if ((arity == ARITY_NONE && np != 0) || (arity == ARITY_ONE_PLUS && np == 0)) {
        goto fail;
    }
    out->packages = calloc(np ? np : 1, sizeof *out->packages);
    if (out->packages == NULL) {
        goto fail;
    }
    for (size_t i = 0; i < np; i++) {
        const char *name = str_clean(json_array_get(jpk, i));
        if (name == NULL || !name_ok(name)) {
            goto fail;
        }
        for (size_t j = 0; j < i; j++) { /* refuse duplicate requested packages */
            if (strcmp(out->packages[j], name) == 0) {
                goto fail;
            }
        }
        out->packages[i] = strdup(name);
        if (out->packages[i] == NULL) {
            goto fail;
        }
        out->npackages = i + 1;
    }

    json_decref(root);
    return 0;

fail:
    json_decref(root);
    pkgx_request_free(out);
    *errcode = ec;
    return -1;
}

void pkgx_request_free(pkgx_request *req) {
    if (req == NULL) {
        return;
    }
    explicit_bzero(req->effect_receipt, sizeof req->effect_receipt);
    if (req->packages != NULL) {
        for (size_t i = 0; i < req->npackages; i++) {
            free(req->packages[i]);
        }
        free(req->packages);
        req->packages = NULL;
        req->npackages = 0;
    }
}

/* ---- preview request (verb-carrying, receipt-free) -------------------- */

static const char *PREVIEW_ALLOWED[] = {"schema_version", "verb", "packages"};

static int is_preview_key(const char *k) {
    for (size_t i = 0; i < sizeof PREVIEW_ALLOWED / sizeof *PREVIEW_ALLOWED; i++) {
        if (strcmp(k, PREVIEW_ALLOWED[i]) == 0) {
            return 1;
        }
    }
    return 0;
}

int pkgx_parse_preview_request(const char *body, size_t len,
                               pkgx_preview_request *out, const char **errcode) {
    memset(out, 0, sizeof *out);
    json_error_t err;
    json_t *root = json_loadb(body, len, JSON_REJECT_DUPLICATES, &err);
    if (root == NULL) {
        *errcode = "bad_json";
        return -1;
    }
    const char *ec = "schema_invalid";
    if (!json_is_object(root) || depth(root) > PKGX_MAX_DEPTH) {
        goto fail;
    }
    {
        const char *k;
        json_t *v;
        json_object_foreach(root, k, v) {
            if (!is_preview_key(k)) {
                goto fail;
            }
        }
    }

    json_t *js = json_object_get(root, "schema_version");
    if (!json_is_integer(js) || json_integer_value(js) != 1) {
        goto fail;
    }

    const char *verb = str_clean(json_object_get(root, "verb"));
    if (verb == NULL) {
        goto fail;
    }
    int arity = verb_arity(verb);
    if (arity < 0) {
        ec = "unknown_request"; /* verb outside the nine-verb allowlist */
        goto fail;
    }
    if (strlen(verb) >= sizeof out->verb) { /* unreachable: every verb fits */
        goto fail;
    }
    strcpy(out->verb, verb);

    json_t *jpk = json_object_get(root, "packages");
    if (!json_is_array(jpk)) {
        goto fail;
    }
    size_t np = json_array_size(jpk);
    if (np > PKGX_MAX_PACKAGES) {
        goto fail;
    }
    if ((arity == ARITY_NONE && np != 0) || (arity == ARITY_ONE_PLUS && np == 0)) {
        goto fail;
    }
    out->packages = calloc(np ? np : 1, sizeof *out->packages);
    if (out->packages == NULL) {
        goto fail;
    }
    for (size_t i = 0; i < np; i++) {
        const char *name = str_clean(json_array_get(jpk, i));
        if (name == NULL || !name_ok(name)) {
            goto fail;
        }
        for (size_t j = 0; j < i; j++) { /* refuse duplicate requested packages */
            if (strcmp(out->packages[j], name) == 0) {
                goto fail;
            }
        }
        out->packages[i] = strdup(name);
        if (out->packages[i] == NULL) {
            goto fail;
        }
        out->npackages = i + 1;
    }

    json_decref(root);
    return 0;

fail:
    json_decref(root);
    pkgx_preview_request_free(out);
    *errcode = ec;
    return -1;
}

void pkgx_preview_request_free(pkgx_preview_request *req) {
    if (req == NULL) {
        return;
    }
    if (req->packages != NULL) {
        for (size_t i = 0; i < req->npackages; i++) {
            free(req->packages[i]);
        }
        free(req->packages);
        req->packages = NULL;
        req->npackages = 0;
    }
}
