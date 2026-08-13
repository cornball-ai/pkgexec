/* The commit gate + the four per-mechanism plan variants. Two things are under
 * test:
 *   1. pkgx_effect_gate fires the committer EXACTLY for PKGX_PLAN_OK and for no
 *      other plan result — asserted directly over every enum value, and through
 *      each mechanism's plan step with a fake transport + fake committer.
 *   2. A committer never runs when policy or redeem refused, when the plan was a
 *      no-op, or when the correlation_id did not match — the on-path proof that
 *      a refused or unredeemed plan cannot mutate the host.
 * Pure C, fake transport, fake committer; no libapt, no broker. ASan/UBSan. */
#include "../src/digest.h"
#include "../src/effect.h"
#include "../src/plan.h"

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

typedef struct {
    const char *body;
} fake_tx_ctx;

static int fake_tx(void *ctx, const char *req, size_t reqlen, char **resp,
                  size_t *resplen) {
    (void) req;
    (void) reqlen;
    fake_tx_ctx *f = ctx;
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

    /* A. package transaction: clean plan -> commit once with the cid. */
    pkgx_txn_record clean[] = {{"nginx", "amd64", "install", "", "1.0", NULL, 0}};
    tx = (fake_tx_ctx){REDEEM_OK};
    fc = (fake_committer_ctx){0, "", 0};
    memset(out, 0, sizeof out);
    detail = "";
    pr = pkgx_plan_and_redeem("apt.install", clean, 1, targets, 1, RECEIPT, 1000,
                              1, CID, fake_tx, &tx, out, &detail);
    CHECK(pkgx_effect_gate(pr, out, commit_fake, &fc) == PKGX_EFFECT_OK &&
              fc.calls == 1 && strcmp(fc.cid, CID) == 0,
          "txn: clean plan redeems and commits once");

    /* A. committer failure -> COMMIT_FAILED (receipt already spent). */
    tx = (fake_tx_ctx){REDEEM_OK};
    fc = (fake_committer_ctx){0, "", 1};
    memset(out, 0, sizeof out);
    pr = pkgx_plan_and_redeem("apt.install", clean, 1, targets, 1, RECEIPT, 1000,
                              1, CID, fake_tx, &tx, out, &detail);
    CHECK(pkgx_effect_gate(pr, out, commit_fake, &fc) == PKGX_EFFECT_COMMIT_FAILED &&
              fc.calls == 1,
          "txn: redeem_ok then commit failure -> COMMIT_FAILED");

    /* A. empty transaction -> NO_OP, receipt never spent, no commit. */
    tx = (fake_tx_ctx){REDEEM_OK};
    fc = (fake_committer_ctx){0, "", 0};
    pr = pkgx_plan_and_redeem("apt.install", NULL, 0, targets, 1, RECEIPT, 1000,
                              1, CID, fake_tx, &tx, out, &detail);
    CHECK(pkgx_effect_gate(pr, out, commit_fake, &fc) == PKGX_EFFECT_NO_OP &&
              fc.calls == 0,
          "txn: empty plan -> NO_OP, no commit");

    /* A. rapt-owned package -> NOT_OWNED before redeem, no commit. */
    pkgx_txn_record owned[] = {{"r-base-core", "amd64", "install", "", "4.4",
                               NULL, 0}};
    tx = (fake_tx_ctx){REDEEM_OK};
    fc = (fake_committer_ctx){0, "", 0};
    pr = pkgx_plan_and_redeem("apt.install", owned, 1, targets, 1, RECEIPT, 1000,
                              1, CID, fake_tx, &tx, out, &detail);
    CHECK(pkgx_effect_gate(pr, out, commit_fake, &fc) == PKGX_EFFECT_REFUSED &&
              fc.calls == 0,
          "txn: rapt-owned -> REFUSED, no commit");

    /* A. redeem refused -> REFUSED, no commit. */
    tx = (fake_tx_ctx){REFUSED};
    fc = (fake_committer_ctx){0, "", 0};
    pr = pkgx_plan_and_redeem("apt.install", clean, 1, targets, 1, RECEIPT, 1000,
                              1, CID, fake_tx, &tx, out, &detail);
    CHECK(pkgx_effect_gate(pr, out, commit_fake, &fc) == PKGX_EFFECT_REFUSED &&
              fc.calls == 0,
          "txn: redeem refused -> REFUSED, no commit");

    /* A. reply carries a different correlation_id -> cid mismatch, no commit. */
    tx = (fake_tx_ctx){REDEEM_OK_OTHER};
    fc = (fake_committer_ctx){0, "", 0};
    pr = pkgx_plan_and_redeem("apt.install", clean, 1, targets, 1, RECEIPT, 1000,
                              1, CID, fake_tx, &tx, out, &detail);
    CHECK(pkgx_effect_gate(pr, out, commit_fake, &fc) == PKGX_EFFECT_REFUSED &&
              fc.calls == 0 && strcmp(detail, "cid_mismatch") == 0,
          "txn: substituted cid -> REFUSED, no commit");

    /* B. update: clean source set -> commit once. */
    const char *comps[] = {"main"};
    pkgx_src_record srcs[] = {
        {"http://deb.debian.org/debian", "stable", comps, 1, NULL, NULL, 0}};
    tx = (fake_tx_ctx){REDEEM_OK};
    fc = (fake_committer_ctx){0, "", 0};
    pr = pkgx_plan_and_redeem_update(srcs, 1, "", RECEIPT, 1000, 1, CID, fake_tx,
                                     &tx, out, &detail);
    CHECK(pkgx_effect_gate(pr, out, commit_fake, &fc) == PKGX_EFFECT_OK &&
              fc.calls == 1 && strcmp(fc.cid, CID) == 0,
          "update: clean source set redeems and commits once");

    /* B. empty source set -> NO_OP, no commit. */
    tx = (fake_tx_ctx){REDEEM_OK};
    fc = (fake_committer_ctx){0, "", 0};
    pr = pkgx_plan_and_redeem_update(NULL, 0, "", RECEIPT, 1000, 1, CID, fake_tx,
                                     &tx, out, &detail);
    CHECK(pkgx_effect_gate(pr, out, commit_fake, &fc) == PKGX_EFFECT_NO_OP &&
              fc.calls == 0,
          "update: empty source set -> NO_OP, no commit");

    /* C. hold: clean selection change -> commit once. */
    const char *ht[] = {"nginx"};
    pkgx_hold_record holds[] = {{"nginx", "install", "hold"}};
    tx = (fake_tx_ctx){REDEEM_OK};
    fc = (fake_committer_ctx){0, "", 0};
    pr = pkgx_plan_and_redeem_hold("apt.hold", holds, 1, ht, 1, RECEIPT, 1000, 1,
                                   CID, fake_tx, &tx, out, &detail);
    CHECK(pkgx_effect_gate(pr, out, commit_fake, &fc) == PKGX_EFFECT_OK &&
              fc.calls == 1,
          "hold: clean selection change redeems and commits once");

    /* C. holding a rapt-owned package -> NOT_OWNED before redeem, no commit. */
    pkgx_hold_record owned_hold[] = {{"r-base-core", "install", "hold"}};
    const char *oht[] = {"r-base-core"};
    tx = (fake_tx_ctx){REDEEM_OK};
    fc = (fake_committer_ctx){0, "", 0};
    pr = pkgx_plan_and_redeem_hold("apt.hold", owned_hold, 1, oht, 1, RECEIPT,
                                   1000, 1, CID, fake_tx, &tx, out, &detail);
    CHECK(pkgx_effect_gate(pr, out, commit_fake, &fc) == PKGX_EFFECT_REFUSED &&
              fc.calls == 0 && strcmp(detail, "r-base-core") == 0,
          "hold: rapt-owned -> REFUSED, no commit");

    /* D. configure: pending set -> commit once. */
    pkgx_cfg_record cfgs[] = {{"nginx", "amd64", "1.0", "half-configured"}};
    tx = (fake_tx_ctx){REDEEM_OK};
    fc = (fake_committer_ctx){0, "", 0};
    pr = pkgx_plan_and_redeem_configure(cfgs, 1, RECEIPT, 1000, 1, CID, fake_tx,
                                        &tx, out, &detail);
    CHECK(pkgx_effect_gate(pr, out, commit_fake, &fc) == PKGX_EFFECT_OK &&
              fc.calls == 1,
          "configure: pending set redeems and commits once");

    /* D. empty pending set -> NO_OP, no commit. */
    tx = (fake_tx_ctx){REDEEM_OK};
    fc = (fake_committer_ctx){0, "", 0};
    pr = pkgx_plan_and_redeem_configure(NULL, 0, RECEIPT, 1000, 1, CID, fake_tx,
                                        &tx, out, &detail);
    CHECK(pkgx_effect_gate(pr, out, commit_fake, &fc) == PKGX_EFFECT_NO_OP &&
              fc.calls == 0,
          "configure: empty pending set -> NO_OP, no commit");

    printf("%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
