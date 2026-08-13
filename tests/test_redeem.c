/* Broker redeem client: strict reply validation + correlation_id equality,
 * exercised with a fake transport against the vendored broker response bodies
 * (the same corpus the broker emits) plus malformed replies. The fake also
 * PARSES and asserts the outgoing request, so a misspelled field or a wrong
 * resource/hash/uid/token would fail rather than pass silently. Built against
 * system Jansson with ASan/UBSan (see Makefile). */
#include "../src/redeem.h"

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

#define FX "tests/fixtures/broker-frames/"
#define CID "00001786382512165708-a061ec02cffe1b2b"
#define RECEIPT "1b9d6bcd1e7f4a3bd2c5e8f0a4d7c9e2"
#define OP "apt.install"
#define RESOURCE "nginx"
#define HASH "80a7a295ea0b737188f9a3e7b41a2aa9423d7a88da22b85e0f79e5350af9a774"

typedef struct {
    const char *body;
    int fail;
    int assert_req; /* 1 = parse and check the outgoing request */
} fake_ctx;

static int seq(json_t *o, const char *k, const char *want) {
    json_t *v = json_object_get(o, k);
    return json_is_string(v) && strcmp(json_string_value(v), want) == 0;
}

static int fake_tx(void *ctx, const char *req, size_t reqlen, char **resp,
                  size_t *resplen) {
    fake_ctx *f = ctx;
    if (f->assert_req) {
        json_error_t e;
        json_t *o = json_loadb(req, reqlen, JSON_REJECT_DUPLICATES, &e);
        CHECK(o != NULL && json_is_object(o), "request is a JSON object");
        json_t *eff = o ? json_object_get(o, "effect") : NULL;
        CHECK(o && seq(o, "type", "redeem_receipt"), "request type=redeem_receipt");
        CHECK(o && seq(o, "effect_receipt", RECEIPT), "request carries the token");
        CHECK(o && json_is_integer(json_object_get(o, "principal_uid")) &&
                  json_integer_value(json_object_get(o, "principal_uid")) == 1000,
              "request principal_uid=1000");
        CHECK(json_is_object(eff), "request has effect object");
        CHECK(eff && seq(eff, "operation", OP), "effect.operation");
        CHECK(eff && seq(eff, "resource", RESOURCE), "effect.resource");
        CHECK(eff && json_is_integer(json_object_get(eff, "plan_schema")) &&
                  json_integer_value(json_object_get(eff, "plan_schema")) == 1,
              "effect.plan_schema=1");
        CHECK(eff && seq(eff, "plan_hash", HASH), "effect.plan_hash");
        /* exact schema: no extra top-level or effect keys */
        CHECK(o && json_object_size(o) == 4, "request has exactly 4 top-level keys");
        CHECK(eff && json_object_size(eff) == 4, "effect has exactly 4 keys");
        json_decref(o);
    }
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
    while (got > 0 && (b[got - 1] == '\n' || b[got - 1] == '\r')) {
        b[--got] = '\0';
    }
    return b;
}

static pkgx_redeem_status run(const char *body, const char *expected_cid,
                             char out_cid[PKGX_CID_LEN + 1], const char **code) {
    pkgx_redeem_req r = {RECEIPT, 1000, OP, RESOURCE, 1, HASH};
    fake_ctx f = {body, 0, 1};
    return pkgx_redeem(&r, expected_cid, fake_tx, &f, out_cid, code);
}

static void expect_refused(const char *body, const char *want_code, const char *lbl) {
    char out[PKGX_CID_LEN + 1] = {0};
    const char *code = "";
    CHECK(run(body, CID, out, &code) == PKGX_REDEEM_REFUSED &&
              strcmp(code, want_code) == 0,
          lbl);
}

int main(void) {
    char out[PKGX_CID_LEN + 1];
    const char *code;

    char *ok = slurp("redeem_ok.json");
    memset(out, 0, sizeof out);
    code = "";
    CHECK(ok != NULL, "redeem_ok fixture present");
    CHECK(run(ok, CID, out, &code) == PKGX_REDEEM_OK && strcmp(out, CID) == 0 &&
              strcmp(code, "ok") == 0,
          "redeem_ok with matching cid -> OK");

    memset(out, 0, sizeof out);
    code = "";
    CHECK(run(ok, "00000000000000000000-0000000000000000", out, &code) ==
                  PKGX_REDEEM_CID_MISMATCH &&
              strcmp(code, "cid_mismatch") == 0,
          "redeem_ok with substituted cid -> CID_MISMATCH");
    free(ok);

    /* every closed-set error maps to REFUSED with its code */
    char *e;
#define REFUSE_FIXTURE(f, c)                                                   \
    do {                                                                       \
        e = slurp(f);                                                          \
        expect_refused(e, c, f);                                               \
        free(e);                                                               \
    } while (0)
    REFUSE_FIXTURE("error_receipt_invalid.json", "receipt_invalid");
    REFUSE_FIXTURE("error_receipt_expired.json", "receipt_expired");
    REFUSE_FIXTURE("error_receipt_redeemed.json", "receipt_redeemed");
    REFUSE_FIXTURE("error_receipt_mismatch.json", "receipt_mismatch");
    REFUSE_FIXTURE("error_receipt_unauthorized.json", "receipt_unauthorized");
    REFUSE_FIXTURE("error_receipt_actor_mismatch.json", "receipt_actor_mismatch");
    /* the broker's operational refusals during redemption */
    expect_refused("{\"error\":\"rate_limited\",\"message\":\"per-uid rate exceeded\","
                   "\"ok\":false}",
                   "rate_limited", "rate_limited -> REFUSED");
    expect_refused("{\"error\":\"persist_failed\",\"message\":\"sink append failed\","
                   "\"ok\":false}",
                   "persist_failed", "persist_failed -> REFUSED");

    /* --- malformed / protocol-violation replies -> PROTOCOL --- */
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

    /* transport failure -> PROTOCOL(transport); request still asserted */
    {
        pkgx_redeem_req r = {RECEIPT, 1000, OP, RESOURCE, 1, HASH};
        fake_ctx f = {"", 1, 1};
        CHECK(pkgx_redeem(&r, CID, fake_tx, &f, out, &code) == PKGX_REDEEM_PROTOCOL &&
                  strcmp(code, "transport") == 0,
              "transport failure -> PROTOCOL(transport)");
    }

    printf("%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
