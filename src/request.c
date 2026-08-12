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

/* Broker correlation id: a bounded string over [0-9a-f-] (a minted counter,
 * dash, hex). Validated for injection safety (it is later stamped into apt's
 * transaction log), not for an exact broker-internal shape. */
static int cid_ok(const char *s) {
    size_t n = strlen(s);
    if (n < 16 || n > PKGX_CID_MAX) {
        return 0;
    }
    for (size_t i = 0; i < n; i++) {
        char c = s[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || c == '-')) {
            return 0;
        }
    }
    return 1;
}

/* Strict apt package name, optionally arch-qualified: a Debian package name
 * ([a-z0-9] then [a-z0-9+.-], >= 2 chars) with an optional ":<arch>" suffix
 * ([a-z0-9-]+). */
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
            if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-')) {
                return 0;
            }
        }
    }
    return 1;
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

/* Per-verb package arity. -1 = unknown verb. */
enum { ARITY_NONE, ARITY_ONE_PLUS, ARITY_ANY };
static int verb_arity(const char *verb) {
    if (strcmp(verb, "apt.update") == 0 || strcmp(verb, "apt.configure") == 0) {
        return ARITY_NONE;
    }
    if (strcmp(verb, "apt.install") == 0 || strcmp(verb, "apt.remove") == 0 ||
        strcmp(verb, "apt.purge") == 0 || strcmp(verb, "apt.hold") == 0 ||
        strcmp(verb, "apt.unhold") == 0) {
        return ARITY_ONE_PLUS;
    }
    if (strcmp(verb, "apt.upgrade") == 0 || strcmp(verb, "apt.dist_upgrade") == 0) {
        return ARITY_ANY;
    }
    return -1;
}

/* ---- stdin read with cap + deadline ---------------------------------- */

int pkgx_read_stdin(int fd, char **body, size_t *len, const char **errcode) {
    struct timespec start;
    clock_gettime(CLOCK_MONOTONIC, &start);
    size_t cap = 4096, n = 0;
    char *buf = malloc(cap + 1);
    if (buf == NULL) {
        *errcode = "io";
        return -1;
    }
    for (;;) {
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        long elapsed = (now.tv_sec - start.tv_sec) * 1000 +
                       (now.tv_nsec - start.tv_nsec) / 1000000;
        long remaining = (long) PKGX_STDIN_DEADLINE_SEC * 1000 - elapsed;
        if (remaining <= 0) {
            free(buf);
            *errcode = "deadline";
            return -1;
        }
        struct pollfd pfd = {.fd = fd, .events = POLLIN};
        int pr = poll(&pfd, 1, (int) remaining);
        if (pr < 0) {
            if (errno == EINTR) {
                continue;
            }
            free(buf);
            *errcode = "io";
            return -1;
        }
        if (pr == 0) {
            free(buf);
            *errcode = "deadline";
            return -1;
        }
        if (n == cap) {
            size_t nc = cap * 2;
            if (nc > PKGX_MAX_STDIN + 1) {
                nc = PKGX_MAX_STDIN + 1;
            }
            char *nb = realloc(buf, nc + 1);
            if (nb == NULL) {
                free(buf);
                *errcode = "io";
                return -1;
            }
            buf = nb;
            cap = nc;
        }
        ssize_t r = read(fd, buf + n, cap - n);
        if (r < 0) {
            if (errno == EINTR) {
                continue;
            }
            free(buf);
            *errcode = "io";
            return -1;
        }
        if (r == 0) {
            break; /* EOF */
        }
        n += (size_t) r;
        if (n > PKGX_MAX_STDIN) {
            free(buf);
            *errcode = "too_large";
            return -1;
        }
    }
    buf[n] = '\0';
    *body = buf;
    *len = n;
    return 0;
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

    json_t *jr = json_object_get(root, "effect_receipt");
    if (!json_is_string(jr) || !is_lc_hex(json_string_value(jr), PKGX_RECEIPT_HEXLEN)) {
        goto fail;
    }
    memcpy(out->effect_receipt, json_string_value(jr), PKGX_RECEIPT_HEXLEN + 1);

    json_t *jc = json_object_get(root, "correlation_id");
    if (!json_is_string(jc) || !cid_ok(json_string_value(jc))) {
        goto fail;
    }
    strcpy(out->correlation_id, json_string_value(jc));

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
        ec = "schema_invalid";
        goto fail;
    }
    for (size_t i = 0; i < np; i++) {
        json_t *e = json_array_get(jpk, i);
        if (!json_is_string(e) || !name_ok(json_string_value(e))) {
            goto fail;
        }
        out->packages[i] = strdup(json_string_value(e));
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
    if (req == NULL || req->packages == NULL) {
        return;
    }
    for (size_t i = 0; i < req->npackages; i++) {
        free(req->packages[i]);
    }
    free(req->packages);
    req->packages = NULL;
    req->npackages = 0;
}
