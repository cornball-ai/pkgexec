/* The non-committing plan step: policy short-circuits before any receipt is
 * spent; a clean plan redeems and validates cid equality. Fake transport, no
 * libapt. ASan/UBSan (Makefile). */
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
#define REDEEM_OK "{\"correlation_id\":\"" CID "\",\"ok\":true,\"persisted\":true}"

typedef struct {
    const char *body;
    int calls;
} fake_ctx;

static int fake_tx(void *ctx, const char *req, size_t reqlen, char **resp,
                  size_t *resplen) {
    (void) req;
    (void) reqlen;
    fake_ctx *f = ctx;
    f->calls++;
    char *b = malloc(strlen(f->body) + 1);
    if (b == NULL) {
        return -1;
    }
    strcpy(b, f->body);
    *resp = b;
    *resplen = strlen(b);
    return 0;
}

static pkgx_plan_result plan(const pkgx_txn_record *recs, size_t n,
                            const char *const *targets, size_t nt,
                            const char *expected_cid, const char *reply,
                            int *calls, const char **detail) {
    fake_ctx f = {reply, 0};
    char out[PKGX_CID_LEN + 1] = {0};
    pkgx_plan_result r = pkgx_plan_and_redeem(
        "apt.install", recs, n, targets, nt, "1b9d6bcd1e7f4a3bd2c5e8f0a4d7c9e2",
        1000, 1, expected_cid, fake_tx, &f, out, detail);
    *calls = f.calls;
    return r;
}

int main(void) {
    const char *targets[] = {"nginx"};
    const char *detail = "";
    int calls = 0;

    pkgx_txn_record clean[] = {{"nginx", "amd64", "install", "", "1.0", NULL, 0}};
    CHECK(plan(clean, 1, targets, 1, CID, REDEEM_OK, &calls, &detail) == PKGX_PLAN_OK &&
              calls == 1,
          "clean plan redeems -> OK");

    /* policy refusals never spend the receipt (transport not called) */
    pkgx_txn_record owned[] = {{"r-base-core", "amd64", "install", "", "4.4", NULL, 0}};
    CHECK(plan(owned, 1, targets, 1, CID, REDEEM_OK, &calls, &detail) ==
                  PKGX_PLAN_NOT_OWNED &&
              calls == 0 && strcmp(detail, "r-base-core") == 0,
          "rapt package -> NOT_OWNED, no redeem");

    const char *hold[] = {"hold"};
    pkgx_txn_record held[] = {{"nginx", "amd64", "upgrade", "1.0", "1.1", hold, 1}};
    CHECK(plan(held, 1, targets, 1, CID, REDEEM_OK, &calls, &detail) == PKGX_PLAN_HELD &&
              calls == 0,
          "held package -> HELD, no redeem");

    const char *ess[] = {"essential"};
    pkgx_txn_record prot[] = {{"bash", "amd64", "remove", "5.2", "", ess, 1}};
    CHECK(plan(prot, 1, targets, 1, CID, REDEEM_OK, &calls, &detail) ==
                  PKGX_PLAN_PROTECTED &&
              calls == 0,
          "essential removal -> PROTECTED, no redeem");

    /* redeem-side refusals map to no_intent */
    CHECK(plan(clean, 1, targets, 1, CID,
               "{\"error\":\"receipt_mismatch\",\"message\":\"x\",\"ok\":false}",
               &calls, &detail) == PKGX_PLAN_NO_INTENT &&
              strcmp(detail, "receipt_mismatch") == 0,
          "redeem refused -> NO_INTENT(receipt_mismatch)");

    CHECK(plan(clean, 1, targets, 1, "00000000000000000000-0000000000000000",
               REDEEM_OK, &calls, &detail) == PKGX_PLAN_NO_INTENT &&
              strcmp(detail, "cid_mismatch") == 0,
          "substituted cid -> NO_INTENT(cid_mismatch)");

    printf("%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
