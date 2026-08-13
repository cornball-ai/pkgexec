/* Strict stdin-request parsing: per-verb schema, bounds, CID grammar, and the
 * read cap/deadline. Built against system Jansson with ASan/UBSan (see Makefile). */
#include "../src/request.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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

/* Expect parse failure with a specific errcode. */
static void reject(const char *verb, const char *body, const char *want_ec,
                  const char *label) {
    pkgx_request req;
    const char *ec = "";
    int rc = pkgx_parse_request(verb, body, strlen(body), &req, &ec);
    CHECK(rc == -1 && strcmp(ec, want_ec) == 0, label);
    if (rc == 0) {
        pkgx_request_free(&req);
    }
}

/* Read a body through pkgx_read_stdin from a temp file (a regular fd, so no
 * pipe-capacity blocking on the oversize case). */
static int read_via_fd(const char *data, size_t n, char **out, size_t *outlen,
                      const char **ec) {
    FILE *f = tmpfile();
    if (f == NULL) {
        return -2;
    }
    fwrite(data, 1, n, f);
    fflush(f);
    lseek(fileno(f), 0, SEEK_SET);
    int rc = pkgx_read_stdin(fileno(f), out, outlen, ec);
    fclose(f);
    return rc;
}

static const char *R = "1b9d6bcd1e7f4a3bd2c5e8f0a4d7c9e2";
static const char *C = "00001786382512165708-a061ec02cffe1b2b";

int main(void) {
    char body[1024];

    /* --- valid, per verb --- */
    snprintf(body, sizeof body,
             "{\"effect_receipt\":\"%s\",\"correlation_id\":\"%s\","
             "\"plan_schema\":1,\"packages\":[\"nginx\"],\"lock_timeout\":30}",
             R, C);
    {
        pkgx_request req;
        const char *ec = "";
        int rc = pkgx_parse_request("apt.install", body, strlen(body), &req, &ec);
        CHECK(rc == 0, "valid install parses");
        if (rc == 0) {
            CHECK(req.npackages == 1 && strcmp(req.packages[0], "nginx") == 0,
                  "install package captured");
            CHECK(strcmp(req.effect_receipt, R) == 0, "receipt captured");
            CHECK(strcmp(req.correlation_id, C) == 0, "cid captured");
            CHECK(req.plan_schema == 1 && req.lock_timeout == 30, "scalars captured");
            pkgx_request_free(&req);
        }
    }

    /* update takes no packages */
    snprintf(body, sizeof body,
             "{\"effect_receipt\":\"%s\",\"correlation_id\":\"%s\","
             "\"plan_schema\":1,\"packages\":[],\"lock_timeout\":0}", R, C);
    {
        pkgx_request req;
        const char *ec = "";
        int rc = pkgx_parse_request("apt.update", body, strlen(body), &req, &ec);
        CHECK(rc == 0 && req.npackages == 0, "valid update (empty packages) parses");
        if (rc == 0) {
            pkgx_request_free(&req);
        }
    }
    /* upgrade is whole-system in v1: targetless parses, targets are rejected */
    {
        pkgx_request req;
        const char *ec = "";
        int rc = pkgx_parse_request("apt.upgrade", body, strlen(body), &req, &ec);
        CHECK(rc == 0 && req.npackages == 0, "targetless upgrade parses");
        if (rc == 0) {
            pkgx_request_free(&req);
        }
    }
    snprintf(body, sizeof body,
             "{\"effect_receipt\":\"%s\",\"correlation_id\":\"%s\","
             "\"plan_schema\":1,\"packages\":[\"nginx\"],\"lock_timeout\":0}", R, C);
    reject("apt.upgrade", body, "schema_invalid",
           "upgrade with a package is refused (whole-system only in v1)");
    reject("apt.dist_upgrade", body, "schema_invalid",
           "dist_upgrade with a package is refused (whole-system only in v1)");

    /* --- per-verb arity refusals --- */
    snprintf(body, sizeof body,
             "{\"effect_receipt\":\"%s\",\"correlation_id\":\"%s\","
             "\"plan_schema\":1,\"packages\":[\"nginx\"],\"lock_timeout\":0}", R, C);
    reject("apt.update", body, "schema_invalid", "update with a package is refused");
    snprintf(body, sizeof body,
             "{\"effect_receipt\":\"%s\",\"correlation_id\":\"%s\","
             "\"plan_schema\":1,\"packages\":[],\"lock_timeout\":0}", R, C);
    reject("apt.install", body, "schema_invalid", "install with no package is refused");

    /* --- field grammar refusals --- */
#define BODY(recpt, cid, ps, pkgs, to)                                          \
    snprintf(body, sizeof body,                                                \
             "{\"effect_receipt\":\"%s\",\"correlation_id\":\"%s\","           \
             "\"plan_schema\":%s,\"packages\":%s,\"lock_timeout\":%s}",        \
             recpt, cid, ps, pkgs, to)

    BODY("1b9d6bcd1e7f4a3bd2c5e8f0a4d7c9e", C, "1", "[\"nginx\"]", "0"); /* 31 hex */
    reject("apt.install", body, "schema_invalid", "short receipt refused");
    BODY("1B9D6BCD1E7F4A3BD2C5E8F0A4D7C9E2", C, "1", "[\"nginx\"]", "0"); /* upper */
    reject("apt.install", body, "schema_invalid", "uppercase receipt refused");
    BODY(R, "bad-cid-with-Z", "1", "[\"nginx\"]", "0");
    reject("apt.install", body, "schema_invalid", "bad cid refused");
    BODY(R, C, "2", "[\"nginx\"]", "0");
    reject("apt.install", body, "schema_invalid", "plan_schema 2 refused");
    BODY(R, C, "\"1\"", "[\"nginx\"]", "0");
    reject("apt.install", body, "schema_invalid", "string plan_schema refused");
    BODY(R, C, "1", "[\"nginx\"]", "-1");
    reject("apt.install", body, "schema_invalid", "negative timeout refused");
    BODY(R, C, "1", "[\"nginx\"]", "3601");
    reject("apt.install", body, "schema_invalid", "over-max timeout refused");
    BODY(R, C, "1", "[\"NGINX\"]", "0");
    reject("apt.install", body, "schema_invalid", "uppercase package refused");
    BODY(R, C, "1", "[\"a\"]", "0");
    reject("apt.install", body, "schema_invalid", "too-short package refused");
    BODY(R, C, "1", "[\"ng inx\"]", "0");
    reject("apt.install", body, "schema_invalid", "package with space refused");
    BODY(R, C, "1", "[\"-bad\"]", "0");
    reject("apt.install", body, "schema_invalid", "leading-dash package refused");

    /* arch-qualified name is accepted */
    BODY(R, C, "1", "[\"libc6:amd64\"]", "0");
    {
        pkgx_request req;
        const char *ec = "";
        int rc = pkgx_parse_request("apt.install", body, strlen(body), &req, &ec);
        CHECK(rc == 0, "arch-qualified package accepted");
        if (rc == 0) {
            pkgx_request_free(&req);
        }
    }

    /* --- exact CID grammar (20 digits, '-', 16 lc hex) --- */
    BODY(R, "0000178638251216570-a061ec02cffe1b2b", "1", "[\"nginx\"]", "0"); /* 19 digits */
    reject("apt.install", body, "schema_invalid", "cid with 19 digits refused");
    BODY(R, "00001786382512165708-A061EC02CFFE1B2B", "1", "[\"nginx\"]", "0"); /* upper hex */
    reject("apt.install", body, "schema_invalid", "cid with uppercase hex refused");
    BODY(R, "00001786382512165708_a061ec02cffe1b2b", "1", "[\"nginx\"]", "0"); /* no dash */
    reject("apt.install", body, "schema_invalid", "cid without the dash refused");

    /* --- duplicate targets, arch leading dash, embedded NUL --- */
    BODY(R, C, "1", "[\"nginx\",\"nginx\"]", "0");
    reject("apt.install", body, "schema_invalid", "duplicate requested package refused");
    BODY(R, C, "1", "[\"libc6:-amd64\"]", "0");
    reject("apt.install", body, "schema_invalid", "leading dash in arch qualifier refused");
    /* jansson rejects an escaped NUL (JSON_ALLOW_NUL is never set); str_clean is
     * defence-in-depth behind it. */
    BODY(R, C, "1", "[\"ng\\u0000inx\"]", "0");
    reject("apt.install", body, "bad_json", "escaped NUL in a string refused");

    /* --- structural refusals --- */
    snprintf(body, sizeof body,
             "{\"effect_receipt\":\"%s\",\"correlation_id\":\"%s\","
             "\"plan_schema\":1,\"packages\":[\"nginx\"],\"lock_timeout\":0,"
             "\"extra\":1}", R, C);
    reject("apt.install", body, "schema_invalid", "unknown member refused");
    snprintf(body, sizeof body,
             "{\"effect_receipt\":\"%s\",\"correlation_id\":\"%s\","
             "\"plan_schema\":1,\"packages\":[\"nginx\"]}", R, C); /* no timeout */
    reject("apt.install", body, "schema_invalid", "missing member refused");
    snprintf(body, sizeof body,
             "{\"effect_receipt\":\"%s\",\"effect_receipt\":\"%s\","
             "\"correlation_id\":\"%s\",\"plan_schema\":1,"
             "\"packages\":[\"nginx\"],\"lock_timeout\":0}", R, R, C);
    reject("apt.install", body, "bad_json", "duplicate key refused");
    snprintf(body, sizeof body,
             "{\"effect_receipt\":\"%s\",\"correlation_id\":\"%s\","
             "\"plan_schema\":1,\"packages\":[\"nginx\"],\"lock_timeout\":0} x",
             R, C);
    reject("apt.install", body, "bad_json", "trailing content refused");
    reject("apt.install", "{", "bad_json", "truncated json refused");
    reject("apt.install", "[1,2]", "schema_invalid", "non-object root refused");
    snprintf(body, sizeof body,
             "{\"effect_receipt\":\"%s\",\"correlation_id\":\"%s\","
             "\"plan_schema\":1,\"packages\":[[[[[\"x\"]]]]],\"lock_timeout\":0}",
             R, C);
    reject("apt.install", body, "schema_invalid", "over-deep nesting refused");
    reject("apt.bogus", body, "unknown_request", "unknown verb refused");

    /* too many packages */
    {
        char *big = malloc(1 << 16);
        int off = snprintf(big, 1 << 16,
                           "{\"effect_receipt\":\"%s\",\"correlation_id\":\"%s\","
                           "\"plan_schema\":1,\"lock_timeout\":0,\"packages\":[", R, C);
        for (int i = 0; i < 257; i++) {
            off += snprintf(big + off, (1 << 16) - off, "%s\"pkg%d\"", i ? "," : "", i);
        }
        off += snprintf(big + off, (1 << 16) - off, "]}");
        reject("apt.install", big, "schema_invalid", "over-256 packages refused");
        free(big);
    }

    /* --- pkgx_read_stdin --- */
    {
        char *out = NULL;
        size_t olen = 0;
        const char *ec = "";
        int rc = read_via_fd("{\"a\":1}", 7, &out, &olen, &ec);
        CHECK(rc == 0 && olen == 7 && memcmp(out, "{\"a\":1}", 7) == 0,
              "read_stdin returns the body");
        free(out);
    }
    {
        size_t n = PKGX_MAX_STDIN + 1;
        char *data = malloc(n);
        memset(data, 'x', n);
        char *out = NULL;
        size_t olen = 0;
        const char *ec = "";
        int rc = read_via_fd(data, n, &out, &olen, &ec);
        CHECK(rc == -1 && strcmp(ec, "too_large") == 0, "read_stdin caps oversize");
        free(out);
        free(data);
    }
    /* deadline: a pipe whose writer stays open with no data trips the (short,
     * injected) deadline rather than blocking. */
    {
        int pfd[2];
        CHECK(pipe(pfd) == 0, "pipe for deadline test");
        char *out = NULL;
        size_t olen = 0;
        const char *ec = "";
        int rc = pkgx_read_stdin_deadline(pfd[0], &out, &olen, &ec, 50);
        CHECK(rc == -1 && strcmp(ec, "deadline") == 0, "read_stdin honors the deadline");
        free(out);
        close(pfd[0]);
        close(pfd[1]);
    }

    printf("%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
