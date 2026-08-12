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

    /* Domain validation: out-of-enum values fail closed, never a valid hash. */
    pkgx_txn_record bad_action = {"nginx", "amd64", "frobnicate", "", "1.0", NULL, 0};
    CHECK(pkgx_digest_pkg_txn("apt.install", &bad_action, 1, hex, NULL, NULL) == -1,
          "unknown action refused");
    const char *bad_flag[] = {"sparkly"};
    pkgx_txn_record badf = {"nginx", "amd64", "install", "", "1.0", bad_flag, 1};
    CHECK(pkgx_digest_pkg_txn("apt.install", &badf, 1, hex, NULL, NULL) == -1,
          "unknown flag name refused");
    const char *dup_flags[] = {"auto", "auto"};
    pkgx_txn_record dupf = {"nginx", "amd64", "install", "", "1.0", dup_flags, 2};
    CHECK(pkgx_digest_pkg_txn("apt.install", &dupf, 1, hex, NULL, NULL) == -1,
          "duplicate flags refused");
    pkgx_txn_record vgood = {"nginx", "amd64", "install", "", "1.0", NULL, 0};
    CHECK(pkgx_digest_pkg_txn("apt.bogus", &vgood, 1, hex, NULL, NULL) == -1,
          "unknown transaction verb refused");
    pkgx_cfg_record badcfg = {"nginx", "amd64", "1.0", "running"};
    CHECK(pkgx_digest_configure(&badcfg, 1, hex, NULL, NULL) == -1,
          "unknown configure state refused");
    pkgx_hold_record badhs = {"nginx", "install", "frozen"};
    CHECK(pkgx_digest_hold("apt.hold", &badhs, 1, hex, NULL, NULL) == -1,
          "unknown hold state refused");
    pkgx_hold_record okh = {"nginx", "install", "hold"};
    CHECK(pkgx_digest_hold("apt.install", &okh, 1, hex, NULL, NULL) == -1,
          "unknown hold verb refused");
    const char *ok_comp[] = {"main"};
    const char *bad_key[] = {"evil"};
    const char *some_val[] = {"x"};
    pkgx_src_record badopt = {"http://x", "noble", ok_comp, 1, bad_key, some_val, 1};
    CHECK(pkgx_digest_update(&badopt, 1, hex, NULL, NULL) == -1,
          "unknown update option key refused");
    const char *dup_key[] = {"trusted", "trusted"};
    const char *dup_val[] = {"yes", "no"};
    pkgx_src_record dupopt = {"http://x", "noble", ok_comp, 1, dup_key, dup_val, 2};
    CHECK(pkgx_digest_update(&dupopt, 1, hex, NULL, NULL) == -1,
          "duplicate update option key refused");
    pkgx_txn_record badutf = {"ng\xff""inx", "amd64", "install", "", "1.0", NULL, 0};
    CHECK(pkgx_digest_pkg_txn("apt.install", &badutf, 1, hex, NULL, NULL) == -1,
          "invalid UTF-8 in a field refused");
    {
        size_t big = 5u * 1024u * 1024u;
        char *huge = malloc(big + 1);
        memset(huge, 'a', big);
        huge[big] = '\0';
        pkgx_txn_record over = {"nginx", "amd64", "install", "", huge, NULL, 0};
        CHECK(pkgx_digest_pkg_txn("apt.install", &over, 1, hex, NULL, NULL) == -1,
              "over-cap canonical size refused");
        free(huge);
    }

    /* Canonical resource: bytewise sort, dedup-refused, empty is "". */
    {
        const char *t[] = {"nginx", "apache2", "curl"};
        char *res = NULL;
        CHECK(pkgx_resource(t, 3, &res) == 0 &&
                  strcmp(res, "apache2,curl,nginx") == 0,
              "resource sorts targets bytewise");
        free(res);
        res = NULL;
        CHECK(pkgx_resource(NULL, 0, &res) == 0 && strcmp(res, "") == 0,
              "empty resource is the empty string");
        free(res);
        const char *dup[] = {"nginx", "nginx"};
        CHECK(pkgx_resource(dup, 2, &res) == -1, "resource refuses duplicate targets");
    }

    json_decref(root);
    printf("%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
