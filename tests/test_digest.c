/* Schema-1 digest encoder vs the shared golden corpus
 * (tests/fixtures/plan-digest/vectors.json, vendored from runix). For each
 * vector the encoder must reproduce the canonical bytes (canonical_hex) AND the
 * SHA-256 (sha256) exactly — both were computed independently of any encoder
 * (printf -> xxd/sha256sum), so this proves the C encoder against an outside
 * authority, not against itself. Built against system Jansson + libcrypto with
 * ASan/UBSan (see Makefile). */
#include "../src/digest.h"

#include <jansson.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int checks = 0;
static int failures = 0;

#define CHECK(cond, msg)                                                     \
    do {                                                                    \
        checks++;                                                           \
        if (!(cond)) {                                                      \
            failures++;                                                     \
            fprintf(stderr, "FAIL: %s (%s:%d)\n", msg, __FILE__, __LINE__); \
        }                                                                  \
    } while (0)

#define FIXTURE "tests/fixtures/plan-digest/vectors.json"

static unsigned char *hexdec(const char *hex, size_t *outlen) {
    size_t n = strlen(hex);
    if (n % 2 != 0) {
        return NULL;
    }
    unsigned char *out = malloc(n / 2 ? n / 2 : 1);
    for (size_t i = 0; i < n / 2; i++) {
        unsigned int b;
        if (sscanf(hex + 2 * i, "%2x", &b) != 1) {
            free(out);
            return NULL;
        }
        out[i] = (unsigned char) b;
    }
    *outlen = n / 2;
    return out;
}

static const char *S(json_t *o, const char *k) {
    const char *v = json_string_value(json_object_get(o, k));
    return v ? v : "";
}

static const char **strarr(json_t *arr, size_t *n) {
    *n = json_array_size(arr);
    const char **v = calloc(*n ? *n : 1, sizeof *v);
    for (size_t i = 0; i < *n; i++) {
        v[i] = json_string_value(json_array_get(arr, i));
    }
    return v;
}

/* Compare the encoder's output against a vector's goldens. */
static void expect(const char *name, int rc, const char *out_hex,
                   unsigned char *canon, size_t clen, const char *want_sha,
                   const char *want_canon_hex) {
    char msg[256];
    snprintf(msg, sizeof msg, "%s: encode ok", name);
    CHECK(rc == 0, msg);
    if (rc != 0) {
        return;
    }
    size_t wlen = 0;
    unsigned char *want = hexdec(want_canon_hex, &wlen);
    snprintf(msg, sizeof msg, "%s: canonical bytes match", name);
    CHECK(want != NULL && clen == wlen && memcmp(canon, want, wlen) == 0, msg);
    free(want);
    snprintf(msg, sizeof msg, "%s: sha256 matches", name);
    CHECK(strcmp(out_hex, want_sha) == 0, msg);
}

static void run_vector(json_t *v) {
    const char *name = S(v, "name");
    const char *verb = S(v, "verb");
    const char *want_sha = S(v, "sha256");
    const char *want_hex = S(v, "canonical_hex");
    json_t *recs = json_object_get(v, "records");
    size_t nrec = json_array_size(recs);
    char hex[65];
    unsigned char *canon = NULL;
    size_t clen = 0;
    int rc = -1;

    if (strcmp(verb, "apt.configure") == 0) {
        pkgx_cfg_record *r = calloc(nrec ? nrec : 1, sizeof *r);
        for (size_t i = 0; i < nrec; i++) {
            json_t *o = json_array_get(recs, i);
            r[i].package = S(o, "package");
            r[i].architecture = S(o, "architecture");
            r[i].current_version = S(o, "current_version");
            r[i].state = S(o, "state");
        }
        rc = pkgx_digest_configure(r, nrec, hex, &canon, &clen);
        free(r);
    } else if (strcmp(verb, "apt.hold") == 0 || strcmp(verb, "apt.unhold") == 0) {
        pkgx_hold_record *r = calloc(nrec ? nrec : 1, sizeof *r);
        for (size_t i = 0; i < nrec; i++) {
            json_t *o = json_array_get(recs, i);
            r[i].package = S(o, "package");
            r[i].from_state = S(o, "from_state");
            r[i].to_state = S(o, "to_state");
        }
        rc = pkgx_digest_hold(verb, r, nrec, hex, &canon, &clen);
        free(r);
    } else if (strcmp(verb, "apt.update") == 0) {
        pkgx_src_record *r = calloc(nrec ? nrec : 1, sizeof *r);
        const char ***comps = calloc(nrec ? nrec : 1, sizeof *comps);
        const char ***okeys = calloc(nrec ? nrec : 1, sizeof *okeys);
        const char ***ovals = calloc(nrec ? nrec : 1, sizeof *ovals);
        for (size_t i = 0; i < nrec; i++) {
            json_t *o = json_array_get(recs, i);
            r[i].uri = S(o, "uri");
            r[i].suite = S(o, "suite");
            comps[i] = strarr(json_object_get(o, "components"), &r[i].ncomponents);
            r[i].components = comps[i];
            json_t *opts = json_object_get(o, "options");
            size_t no = json_object_size(opts);
            const char **ks = calloc(no ? no : 1, sizeof *ks);
            const char **vs = calloc(no ? no : 1, sizeof *vs);
            size_t j = 0;
            const char *k;
            json_t *val;
            json_object_foreach(opts, k, val) {
                ks[j] = k;
                vs[j] = json_string_value(val);
                j++;
            }
            okeys[i] = ks;
            ovals[i] = vs;
            r[i].opt_keys = ks;
            r[i].opt_vals = vs;
            r[i].nopts = no;
        }
        rc = pkgx_digest_update(r, nrec, hex, &canon, &clen);
        for (size_t i = 0; i < nrec; i++) {
            free((void *) comps[i]);
            free((void *) okeys[i]);
            free((void *) ovals[i]);
        }
        free(comps);
        free(okeys);
        free(ovals);
        free(r);
    } else { /* package transactions */
        pkgx_txn_record *r = calloc(nrec ? nrec : 1, sizeof *r);
        const char ***flags = calloc(nrec ? nrec : 1, sizeof *flags);
        for (size_t i = 0; i < nrec; i++) {
            json_t *o = json_array_get(recs, i);
            r[i].package = S(o, "package");
            r[i].architecture = S(o, "architecture");
            r[i].action = S(o, "action");
            r[i].from_version = S(o, "from_version");
            r[i].to_version = S(o, "to_version");
            flags[i] = strarr(json_object_get(o, "flags"), &r[i].nflags);
            r[i].flags = flags[i];
        }
        rc = pkgx_digest_pkg_txn(verb, r, nrec, hex, &canon, &clen);
        for (size_t i = 0; i < nrec; i++) {
            free((void *) flags[i]);
        }
        free(flags);
        free(r);
    }

    expect(name, rc, hex, canon, clen, want_sha, want_hex);
    free(canon);
}

int main(void) {
    json_error_t err;
    json_t *root = json_load_file(FIXTURE, 0, &err);
    if (root == NULL) {
        fprintf(stderr, "cannot load %s: %s\n", FIXTURE, err.text);
        return 2;
    }
    json_t *vectors = json_object_get(root, "vectors");
    size_t n = json_array_size(vectors);
    CHECK(n == 13, "all 13 golden vectors present");
    for (size_t i = 0; i < n; i++) {
        run_vector(json_array_get(vectors, i));
    }

    /* Delimiter safety is fail-closed: a US in a field refuses (no digest). */
    const char *bad_flags[] = {"au\x1fto"};
    pkgx_txn_record bad = {"nginx", "amd64", "install", "", "1.0", bad_flags, 1};
    char hex[65];
    CHECK(pkgx_digest_pkg_txn("apt.install", &bad, 1, hex, NULL, NULL) == -1,
          "US in a flag value is refused");
    pkgx_hold_record badh = {"ng,inx", "install", "hold"};
    CHECK(pkgx_digest_hold("apt.hold", &badh, 1, hex, NULL, NULL) == -1,
          "comma in a package name is refused");

    json_decref(root);
    printf("%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
