/* Broker redeem client: strict reply validation + correlation_id equality,
 * exercised with a fake transport against the vendored broker response bodies
 * (the same corpus the broker emits) plus malformed replies. Built against
 * system Jansson with ASan/UBSan (see Makefile). */
#include "../src/redeem.h"

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

#define FX "tests/fixtures/broker-frames/"
#define CID "00001786382512165708-a061ec02cffe1b2b"
#define HASH "80a7a295ea0b737188f9a3e7b41a2aa9423d7a88da22b85e0f79e5350af9a774"

typedef struct {
    const char *body;
    int fail;
} fake_ctx;

static int fake_tx(void *ctx, const char *req, size_t reqlen, char **resp,
                  size_t *resplen) {
    (void) req;
    (void) reqlen;
    fake_ctx *f = ctx;
    if (f->fail) {
        *resp = NULL;
        return -1;
    }
    *resp = strdup(f->body);
    *resplen = strlen(f->body);
    return *resp ? 0 : -1;
}

static char *slurp(const char *name) {
    char path[512];
    snprintf(path, sizeof path, "%s%s", FX, name);
    FILE *f = fopen(path, "rb");
    if (f == NULL) {
        return NULL;
    }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *b = malloc((size_t) sz + 1);
    size_t got = fread(b, 1, (size_t) sz, f);
    fclose(f);
    b[got] = '\0';
    /* trim a trailing newline the fixture file may carry */
    while (got > 0 && (b[got - 1] == '\n' || b[got - 1] == '\r')) {
        b[--got] = '\0';
    }
    return b;
}

static pkgx_redeem_status run(const char *body, const char *expected_cid,
                             char out_cid[PKGX_CID_LEN + 1], const char **code) {
    pkgx_redeem_req r = {"1b9d6bcd1e7f4a3bd2c5e8f0a4d7c9e2", 1000, "apt.install",
                         "nginx", 1, HASH};
    fake_ctx f = {body, 0};
    return pkgx_redeem(&r, expected_cid, fake_tx, &f, out_cid, code);
}

static void expect_refused(const char *fixture, const char *want_code) {
    char *body = slurp(fixture);
    char out[PKGX_CID_LEN + 1] = {0};
    const char *code = "";
    char msg[128];
    if (body == NULL) {
        CHECK(0, "fixture missing");
        return;
    }
    pkgx_redeem_status st = run(body, CID, out, &code);
    snprintf(msg, sizeof msg, "%s -> REFUSED(%s)", fixture, want_code);
    CHECK(st == PKGX_REDEEM_REFUSED && strcmp(code, want_code) == 0, msg);
    free(body);
}

int main(void) {
    char out[PKGX_CID_LEN + 1];
    const char *code;

    /* happy path: the real redeem_ok body, matching cid */
    char *ok = slurp("redeem_ok.json");
    memset(out, 0, sizeof out);
    code = "";
    CHECK(ok != NULL, "redeem_ok fixture present");
    CHECK(run(ok, CID, out, &code) == PKGX_REDEEM_OK && strcmp(out, CID) == 0 &&
              strcmp(code, "ok") == 0,
          "redeem_ok with matching cid -> OK");

    /* cid equality: same ok body, a DIFFERENT expected cid -> refuse, no commit */
    memset(out, 0, sizeof out);
    code = "";
    CHECK(run(ok, "00000000000000000000-0000000000000000", out, &code) ==
                  PKGX_REDEEM_CID_MISMATCH &&
              strcmp(code, "cid_mismatch") == 0,
          "redeem_ok with substituted cid -> CID_MISMATCH");
    free(ok);

    /* every closed-set receipt error maps to REFUSED with its code */
    expect_refused("error_receipt_invalid.json", "receipt_invalid");
    expect_refused("error_receipt_expired.json", "receipt_expired");
    expect_refused("error_receipt_redeemed.json", "receipt_redeemed");
    expect_refused("error_receipt_mismatch.json", "receipt_mismatch");
    expect_refused("error_receipt_unauthorized.json", "receipt_unauthorized");
    expect_refused("error_receipt_actor_mismatch.json", "receipt_actor_mismatch");

    /* --- malformed / protocol-violation replies -> PROTOCOL --- */
    memset(out, 0, sizeof out);
    CHECK(run("{\"error\":\"weird\",\"message\":\"x\",\"ok\":false}", CID, out, &code) ==
              PKGX_REDEEM_PROTOCOL,
          "error code outside the closed set -> PROTOCOL");
    CHECK(run("{\"error\":\"effect_without_receipt\",\"message\":\"x\",\"ok\":false}",
              CID, out, &code) == PKGX_REDEEM_PROTOCOL,
          "effect_without_receipt is not a redeem error -> PROTOCOL");
    CHECK(run("{\"correlation_id\":\"" CID "\",\"ok\":true}", CID, out, &code) ==
              PKGX_REDEEM_PROTOCOL,
          "ok reply missing persisted -> PROTOCOL");
    CHECK(run("{\"correlation_id\":\"" CID "\",\"ok\":true,\"persisted\":false}", CID,
              out, &code) == PKGX_REDEEM_PROTOCOL,
          "ok reply persisted:false -> PROTOCOL");
    CHECK(run("{\"correlation_id\":\"" CID "\",\"ok\":true,\"persisted\":true,\"x\":1}",
              CID, out, &code) == PKGX_REDEEM_PROTOCOL,
          "ok reply with an extra key -> PROTOCOL");
    CHECK(run("{\"ok\":true,\"persisted\":true}", CID, out, &code) ==
              PKGX_REDEEM_PROTOCOL,
          "ok reply missing correlation_id -> PROTOCOL");
    CHECK(run("not json", CID, out, &code) == PKGX_REDEEM_PROTOCOL,
          "malformed JSON reply -> PROTOCOL");
    CHECK(run("{\"ok\":1}", CID, out, &code) == PKGX_REDEEM_PROTOCOL,
          "non-boolean ok -> PROTOCOL");

    /* transport failure -> PROTOCOL(transport) */
    {
        pkgx_redeem_req r = {"1b9d6bcd1e7f4a3bd2c5e8f0a4d7c9e2", 1000, "apt.install",
                             "nginx", 1, HASH};
        fake_ctx f = {"", 1};
        CHECK(pkgx_redeem(&r, CID, fake_tx, &f, out, &code) == PKGX_REDEEM_PROTOCOL &&
                  strcmp(code, "transport") == 0,
              "transport failure -> PROTOCOL(transport)");
    }

    printf("%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
