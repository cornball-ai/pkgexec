/* Trusted-side policy enforcement over resolved records. ASan/UBSan (Makefile). */
#include "../src/policy.h"

#include <stdio.h>
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

static pkgx_policy_result one(const char *pkg, const char *action,
                             const char *const *flags, size_t nf,
                             const char **off) {
    pkgx_txn_record r = {pkg, "amd64", action, "", "1.0", flags, nf};
    return pkgx_policy_check(&r, 1, off);
}

int main(void) {
    const char *off = NULL;

    /* --- ownership predicate (pinned rapt pattern) --- */
    CHECK(pkgx_is_rapt_owned("r-cran-jsonlite"), "r-cran-jsonlite is rapt-owned");
    CHECK(pkgx_is_rapt_owned("r-base-core"), "r-base-core is rapt-owned");
    CHECK(pkgx_is_rapt_owned("r-api-4.0"), "r-api-4.0 is rapt-owned");
    CHECK(!pkgx_is_rapt_owned("ruby"), "ruby is not rapt-owned");
    CHECK(!pkgx_is_rapt_owned("rstudio"), "rstudio is not rapt-owned");
    CHECK(!pkgx_is_rapt_owned("r-"), "bare r- is not rapt-owned");
    CHECK(!pkgx_is_rapt_owned("r-cran"), "r-cran (no third part) is not rapt-owned");
    CHECK(!pkgx_is_rapt_owned("libr-foo-bar"), "libr-foo-bar is not rapt-owned");
    CHECK(!pkgx_is_rapt_owned("r-cran-Jsonlite"), "uppercase is not rapt-owned");

    /* --- whole-plan checks --- */
    CHECK(one("nginx", "install", NULL, 0, &off) == PKGX_POLICY_OK, "clean install ok");

    CHECK(one("r-cran-jsonlite", "install", NULL, 0, &off) == PKGX_POLICY_NOT_OWNED &&
              strcmp(off, "r-cran-jsonlite") == 0,
          "rapt package refused not-owned");

    /* an r-* pulled as a dependency of a non-r target still crosses the boundary */
    {
        pkgx_txn_record recs[] = {
            {"nginx", "amd64", "install", "", "1.0", NULL, 0},
            {"r-base-core", "amd64", "install", "", "4.4.1", NULL, 0}};
        CHECK(pkgx_policy_check(recs, 2, &off) == PKGX_POLICY_NOT_OWNED &&
                  strcmp(off, "r-base-core") == 0,
              "rapt dependency in the plan refused not-owned");
    }

    const char *hold[] = {"hold"};
    CHECK(one("nginx", "upgrade", hold, 1, &off) == PKGX_POLICY_HELD &&
              strcmp(off, "nginx") == 0,
          "held package refused");

    const char *ess[] = {"essential"};
    CHECK(one("bash", "remove", ess, 1, &off) == PKGX_POLICY_PROTECTED,
          "removing an essential package refused");
    const char *prot[] = {"protected"};
    CHECK(one("init", "purge", prot, 1, &off) == PKGX_POLICY_PROTECTED,
          "purging a protected package refused");
    CHECK(one("bash", "install", ess, 1, &off) == PKGX_POLICY_OK,
          "installing an essential package is fine (not a removal)");

    printf("%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
