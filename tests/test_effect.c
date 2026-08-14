/* The commit gate + the four per-mechanism plan variants. Three things are under
 * test:
 *   1. pkgx_effect_gate fires the committer EXACTLY for PKGX_PLAN_OK and for no
 *      other plan result — asserted directly over every enum value, and through
 *      each mechanism's plan step. On OK it also refuses a missing/malformed
 *      correlation_id before committing.
 *   2. A committer never runs when policy or redeem refused, when the plan was a
 *      no-op, or when the cid did not match — the on-path proof that a refused
 *      or unredeemed plan cannot mutate the host. apt.configure enforces
 *      ownership: a rapt-owned pending package is refused before the receipt.
 *   3. When a mechanism does redeem, the fake transport PARSES the outgoing
 *      request and asserts its exact operation, resource, plan_hash and key
 *      sets — so wrong mechanism wiring (wrong verb/resource/digest) fails
 *      rather than staying green.
 * Pure C, fake transport, fake committer; no libapt, no broker. ASan/UBSan. */
#include "../src/digest.h"
#include "../src/effect.h"
#include "../src/plan.h"

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

#define CID "00001786382512165708-a061ec02cffe1b2b"
#define OTHER_CID "00000000000000000000-0000000000000000"
#define RECEIPT "1b9d6bcd1e7f4a3bd2c5e8f0a4d7c9e2"
#define REDEEM_OK "{\"correlation_id\":\"" CID "\",\"ok\":true,\"persisted\":true}"
#define REDEEM_OK_OTHER \
    "{\"correlation_id\":\"" OTHER_CID "\",\"ok\":true,\"persisted\":true}"
#define REFUSED "{\"error\":\"receipt_expired\",\"message\":\"x\",\"ok\":false}"

/* ---- fakes ------------------------------------------------------------- */

/* When op != NULL the fake asserts the exact request the plan step built; the
 * expected resource/hash are computed independently by each test. */
typedef struct {
    const char *body;
    const char *op;
    const char *resource;
    const char *hash;
    int calls;
} fake_tx_ctx;

static int seq(json_t *o, const char *k, const char *want) {
    json_t *v = json_object_get(o, k);
    return json_is_string(v) && strcmp(json_string_value(v), want) == 0;
}

static int fake_tx(void *ctx, const char *req, size_t reqlen, char **resp,
                  size_t *resplen) {
    fake_tx_ctx *f = ctx;
    f->calls++;
    if (f->op != NULL) {
        json_error_t e;
        json_t *o = json_loadb(req, reqlen, JSON_REJECT_DUPLICATES, &e);
        json_t *eff = o ? json_object_get(o, "effect") : NULL;
        CHECK(o && seq(o, "type", "redeem_receipt") &&
                  seq(o, "effect_receipt", RECEIPT),
              "request: type + token");
        CHECK(o && json_is_integer(json_object_get(o, "principal_uid")) &&
                  json_integer_value(json_object_get(o, "principal_uid")) == 1000,
              "request: principal_uid");
        CHECK(eff && seq(eff, "operation", f->op), "request: operation");
        CHECK(eff && seq(eff, "resource", f->resource), "request: resource");
        CHECK(eff && json_is_integer(json_object_get(eff, "plan_schema")) &&
                  json_integer_value(json_object_get(eff, "plan_schema")) == 1,
              "request: plan_schema");
        CHECK(eff && seq(eff, "plan_hash", f->hash), "request: plan_hash");
        CHECK(o && json_object_size(o) == 4, "request: 4 top-level keys");
        CHECK(eff && json_object_size(eff) == 4, "request: 4 effect keys");
        json_decref(o);
    }
    char *b = strdup(f->body);
    if (b == NULL) {
        return -1;
    }
    *resp = b;
    *resplen = strlen(b);
    return 0;
}

typedef struct {
    int calls;
    char cid[64];
    int rc; /* the committer's return code */
} fake_committer_ctx;

static int commit_fake(void *ctx, const char *correlation_id) {
    fake_committer_ctx *f = ctx;
    f->calls++;
    snprintf(f->cid, sizeof f->cid, "%s", correlation_id ? correlation_id : "");
    return f->rc;
}

/* ---- the gate over every plan result (direct) -------------------------- */

static void gate_matrix(void) {
    fake_committer_ctx fc;

    /* OK: commit fires once, with the validated cid. */
    fc = (fake_committer_ctx){0, "", 0};
    CHECK(pkgx_effect_gate(PKGX_PLAN_OK, CID, commit_fake, &fc) ==
                  PKGX_EFFECT_OK &&
              fc.calls == 1 && strcmp(fc.cid, CID) == 0,
          "gate: OK commits once with the validated cid");

    /* NO_OP: nothing committed. */
    fc = (fake_committer_ctx){0, "", 0};
    CHECK(pkgx_effect_gate(PKGX_PLAN_NO_OP, "", commit_fake, &fc) ==
                  PKGX_EFFECT_NO_OP &&
              fc.calls == 0,
          "gate: NO_OP commits nothing");

    /* every refusal result commits nothing. */
    const pkgx_plan_result refusals[] = {PKGX_PLAN_NOT_OWNED, PKGX_PLAN_HELD,
                                        PKGX_PLAN_PROTECTED, PKGX_PLAN_NO_INTENT,
                                        PKGX_PLAN_INTERNAL};
    for (size_t i = 0; i < sizeof refusals / sizeof refusals[0]; i++) {
        fc = (fake_committer_ctx){0, "", 0};
        CHECK(pkgx_effect_gate(refusals[i], CID, commit_fake, &fc) ==
                      PKGX_EFFECT_REFUSED &&
                  fc.calls == 0,
              "gate: a refusal result commits nothing");
    }

    /* committer failure on an OK plan surfaces as COMMIT_FAILED. */
    fc = (fake_committer_ctx){0, "", 1};
    CHECK(pkgx_effect_gate(PKGX_PLAN_OK, CID, commit_fake, &fc) ==
                  PKGX_EFFECT_COMMIT_FAILED &&
              fc.calls == 1,
          "gate: committer failure -> COMMIT_FAILED");

    /* NULL committer on an OK plan fails closed (never a silent success). */
    CHECK(pkgx_effect_gate(PKGX_PLAN_OK, CID, NULL, NULL) ==
              PKGX_EFFECT_COMMIT_FAILED,
          "gate: NULL committer on OK fails closed");

    /* a malformed cid on an OK plan fails closed WITHOUT calling the committer:
     * the committer stamps the cid, so garbage must never reach it. */
    fc = (fake_committer_ctx){0, "", 0};
    CHECK(pkgx_effect_gate(PKGX_PLAN_OK, "not-a-valid-cid", commit_fake, &fc) ==
                  PKGX_EFFECT_COMMIT_FAILED &&
              fc.calls == 0,
          "gate: malformed cid on OK fails closed, no commit");

    /* a NULL cid on an OK plan likewise fails closed with no commit. */
    fc = (fake_committer_ctx){0, "", 0};
    CHECK(pkgx_effect_gate(PKGX_PLAN_OK, NULL, commit_fake, &fc) ==
                  PKGX_EFFECT_COMMIT_FAILED &&
              fc.calls == 0,
          "gate: NULL cid on OK fails closed, no commit");
}

/* ---- through each mechanism's plan step -------------------------------- */

int main(void) {
    gate_matrix();

    const char *targets[] = {"nginx"};
    char out[PKGX_CID_LEN + 1];
    const char *detail;
    fake_committer_ctx fc;
    fake_tx_ctx tx;
    pkgx_plan_result pr;
    char exp_hash[PKGEXEC_DIGEST_HEX + 1];
    char *exp_res = NULL;

    /* A. package transaction: clean plan -> commit once; the request carries
     * apt.install, the target resource, and the computed txn digest. */
    pkgx_txn_record clean[] = {{"nginx", "amd64", "install", "", "1.0", NULL, 0}};
    CHECK(pkgx_digest_pkg_txn("apt.install", clean, 1, exp_hash, NULL, NULL) == 0,
          "txn: compute expected digest");
    CHECK(pkgx_resource(targets, 1, &exp_res) == 0, "txn: compute expected resource");
    tx = (fake_tx_ctx){REDEEM_OK, "apt.install", exp_res, exp_hash, 0};
    fc = (fake_committer_ctx){0, "", 0};
    memset(out, 0, sizeof out);
    detail = "";
    pr = pkgx_plan_and_redeem("apt.install", clean, 1, targets, 1, RECEIPT, 1000,
                              1, CID, fake_tx, &tx, out, &detail);
    CHECK(pkgx_effect_gate(pr, out, commit_fake, &fc) == PKGX_EFFECT_OK &&
              fc.calls == 1 && strcmp(fc.cid, CID) == 0 && tx.calls == 1,
          "txn: clean plan redeems and commits once");

    /* A. committer failure -> COMMIT_FAILED (receipt already spent). */
    tx = (fake_tx_ctx){REDEEM_OK, "apt.install", exp_res, exp_hash, 0};
    fc = (fake_committer_ctx){0, "", 1};
    memset(out, 0, sizeof out);
    pr = pkgx_plan_and_redeem("apt.install", clean, 1, targets, 1, RECEIPT, 1000,
                              1, CID, fake_tx, &tx, out, &detail);
    CHECK(pkgx_effect_gate(pr, out, commit_fake, &fc) == PKGX_EFFECT_COMMIT_FAILED &&
              fc.calls == 1,
          "txn: redeem_ok then commit failure -> COMMIT_FAILED");

    /* A. empty transaction -> NO_OP, receipt never spent, no commit. */
    tx = (fake_tx_ctx){REDEEM_OK, NULL, NULL, NULL, 0};
    fc = (fake_committer_ctx){0, "", 0};
    pr = pkgx_plan_and_redeem("apt.install", NULL, 0, targets, 1, RECEIPT, 1000,
                              1, CID, fake_tx, &tx, out, &detail);
    CHECK(pkgx_effect_gate(pr, out, commit_fake, &fc) == PKGX_EFFECT_NO_OP &&
              fc.calls == 0 && tx.calls == 0,
          "txn: empty plan -> NO_OP, no redeem, no commit");

    /* A. rapt-owned package -> NOT_OWNED before redeem, no commit. */
    pkgx_txn_record owned[] = {{"r-base-core", "amd64", "install", "", "4.4",
                               NULL, 0}};
    tx = (fake_tx_ctx){REDEEM_OK, NULL, NULL, NULL, 0};
    fc = (fake_committer_ctx){0, "", 0};
    pr = pkgx_plan_and_redeem("apt.install", owned, 1, targets, 1, RECEIPT, 1000,
                              1, CID, fake_tx, &tx, out, &detail);
    CHECK(pkgx_effect_gate(pr, out, commit_fake, &fc) == PKGX_EFFECT_REFUSED &&
              fc.calls == 0 && tx.calls == 0,
          "txn: rapt-owned -> REFUSED, no redeem, no commit");

    /* A. redeem refused -> REFUSED, no commit (request still well-formed). */
    tx = (fake_tx_ctx){REFUSED, "apt.install", exp_res, exp_hash, 0};
    fc = (fake_committer_ctx){0, "", 0};
    pr = pkgx_plan_and_redeem("apt.install", clean, 1, targets, 1, RECEIPT, 1000,
                              1, CID, fake_tx, &tx, out, &detail);
    CHECK(pkgx_effect_gate(pr, out, commit_fake, &fc) == PKGX_EFFECT_REFUSED &&
              fc.calls == 0 && tx.calls == 1,
          "txn: redeem refused -> REFUSED, no commit");

    /* A. reply carries a different correlation_id -> cid mismatch, no commit. */
    tx = (fake_tx_ctx){REDEEM_OK_OTHER, "apt.install", exp_res, exp_hash, 0};
    fc = (fake_committer_ctx){0, "", 0};
    pr = pkgx_plan_and_redeem("apt.install", clean, 1, targets, 1, RECEIPT, 1000,
                              1, CID, fake_tx, &tx, out, &detail);
    CHECK(pkgx_effect_gate(pr, out, commit_fake, &fc) == PKGX_EFFECT_REFUSED &&
              fc.calls == 0 && strcmp(detail, "cid_mismatch") == 0,
          "txn: substituted cid -> REFUSED, no commit");
    free(exp_res);
    exp_res = NULL;

    /* B. update: clean source set -> commit once; request carries apt.update,
     * resource "" (full refresh), and the source-set digest. */
    const char *comps[] = {"main"};
    pkgx_src_record srcs[] = {
        {"http://deb.debian.org/debian", "stable", comps, 1, NULL, NULL, 0}};
    CHECK(pkgx_digest_update(srcs, 1, exp_hash, NULL, NULL) == 0,
          "update: compute expected digest");
    tx = (fake_tx_ctx){REDEEM_OK, "apt.update", "", exp_hash, 0};
    fc = (fake_committer_ctx){0, "", 0};
    pr = pkgx_plan_and_redeem_update(srcs, 1, "", RECEIPT, 1000, 1, CID, fake_tx,
                                     &tx, out, &detail);
    CHECK(pkgx_effect_gate(pr, out, commit_fake, &fc) == PKGX_EFFECT_OK &&
              fc.calls == 1 && strcmp(fc.cid, CID) == 0 && tx.calls == 1,
          "update: clean source set redeems and commits once");

    /* B. empty source set -> NO_OP, no commit. */
    tx = (fake_tx_ctx){REDEEM_OK, NULL, NULL, NULL, 0};
    fc = (fake_committer_ctx){0, "", 0};
    pr = pkgx_plan_and_redeem_update(NULL, 0, "", RECEIPT, 1000, 1, CID, fake_tx,
                                     &tx, out, &detail);
    CHECK(pkgx_effect_gate(pr, out, commit_fake, &fc) == PKGX_EFFECT_NO_OP &&
              fc.calls == 0 && tx.calls == 0,
          "update: empty source set -> NO_OP, no commit");

    /* C. hold: clean selection change -> commit once; request carries apt.hold,
     * the target resource, and the hold digest. */
    const char *ht[] = {"nginx"};
    pkgx_hold_record holds[] = {{"nginx", "install", "hold"}};
    CHECK(pkgx_digest_hold("apt.hold", holds, 1, exp_hash, NULL, NULL) == 0,
          "hold: compute expected digest");
    CHECK(pkgx_resource(ht, 1, &exp_res) == 0, "hold: compute expected resource");
    tx = (fake_tx_ctx){REDEEM_OK, "apt.hold", exp_res, exp_hash, 0};
    fc = (fake_committer_ctx){0, "", 0};
    pr = pkgx_plan_and_redeem_hold("apt.hold", holds, 1, ht, 1, RECEIPT, 1000, 1,
                                   CID, fake_tx, &tx, out, &detail);
    CHECK(pkgx_effect_gate(pr, out, commit_fake, &fc) == PKGX_EFFECT_OK &&
              fc.calls == 1 && tx.calls == 1,
          "hold: clean selection change redeems and commits once");
    free(exp_res);
    exp_res = NULL;

    /* C. holding a rapt-owned package -> NOT_OWNED before redeem, no commit. */
    pkgx_hold_record owned_hold[] = {{"r-base-core", "install", "hold"}};
    const char *oht[] = {"r-base-core"};
    tx = (fake_tx_ctx){REDEEM_OK, NULL, NULL, NULL, 0};
    fc = (fake_committer_ctx){0, "", 0};
    pr = pkgx_plan_and_redeem_hold("apt.hold", owned_hold, 1, oht, 1, RECEIPT,
                                   1000, 1, CID, fake_tx, &tx, out, &detail);
    CHECK(pkgx_effect_gate(pr, out, commit_fake, &fc) == PKGX_EFFECT_REFUSED &&
              fc.calls == 0 && tx.calls == 0 && strcmp(detail, "r-base-core") == 0,
          "hold: rapt-owned -> REFUSED, no redeem, no commit");

    /* D. configure: pending set -> commit once; request carries apt.configure,
     * resource "pending", and the configure digest. */
    pkgx_cfg_record cfgs[] = {{"nginx", "amd64", "1.0", "half-configured"}};
    CHECK(pkgx_digest_configure(cfgs, 1, exp_hash, NULL, NULL) == 0,
          "configure: compute expected digest");
    tx = (fake_tx_ctx){REDEEM_OK, "apt.configure", "pending", exp_hash, 0};
    fc = (fake_committer_ctx){0, "", 0};
    pr = pkgx_plan_and_redeem_configure(cfgs, 1, RECEIPT, 1000, 1, CID, fake_tx,
                                        &tx, out, &detail);
    CHECK(pkgx_effect_gate(pr, out, commit_fake, &fc) == PKGX_EFFECT_OK &&
              fc.calls == 1 && tx.calls == 1,
          "configure: pending set redeems and commits once");

    /* D. a rapt-owned package in the pending set -> NOT_OWNED before redeem, no
     * commit: configuring it would run its maintainer scripts. */
    pkgx_cfg_record owned_cfg[] = {
        {"r-base-core", "amd64", "4.4", "half-configured"}};
    tx = (fake_tx_ctx){REDEEM_OK, NULL, NULL, NULL, 0};
    fc = (fake_committer_ctx){0, "", 0};
    pr = pkgx_plan_and_redeem_configure(owned_cfg, 1, RECEIPT, 1000, 1, CID,
                                        fake_tx, &tx, out, &detail);
    CHECK(pr == PKGX_PLAN_NOT_OWNED && strcmp(detail, "r-base-core") == 0,
          "configure: rapt-owned pending package -> NOT_OWNED");
    CHECK(pkgx_effect_gate(pr, out, commit_fake, &fc) == PKGX_EFFECT_REFUSED &&
              fc.calls == 0 && tx.calls == 0,
          "configure: rapt-owned pending -> no redeem, no commit");

    /* D. empty pending set -> NO_OP, no commit. */
    tx = (fake_tx_ctx){REDEEM_OK, NULL, NULL, NULL, 0};
    fc = (fake_committer_ctx){0, "", 0};
    pr = pkgx_plan_and_redeem_configure(NULL, 0, RECEIPT, 1000, 1, CID, fake_tx,
                                        &tx, out, &detail);
    CHECK(pkgx_effect_gate(pr, out, commit_fake, &fc) == PKGX_EFFECT_NO_OP &&
              fc.calls == 0 && tx.calls == 0,
          "configure: empty pending set -> NO_OP, no commit");

    printf("%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
