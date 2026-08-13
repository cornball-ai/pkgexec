/* Cross-repo drift alarm: the ownership predicate pkgexec pins
 * (^r-[a-z]+-[a-z0-9.]+$, implemented in policy.c and behaviour-tested in
 * test_policy.c) must stay byte-identical to the one rapt actually applies in
 * r-pkg/R/manager.R. This reads rapt's live source and fails if the pinned
 * pattern is no longer present there. rapt is a separate repo, so where its
 * source is not checked out (CI) the check skips rather than failing — it is a
 * drift alarm that fires wherever rapt is available (e.g. the dev host).
 *
 * Point it at rapt via PKGEXEC_RAPT_MANAGER, else $HOME/rapt/r-pkg/R/manager.R. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PINNED "^r-[a-z]+-[a-z0-9.]+$"

int main(void) {
    const char *path = getenv("PKGEXEC_RAPT_MANAGER");
    char buf[1024];
    if (path == NULL) {
        const char *home = getenv("HOME");
        if (home != NULL) {
            snprintf(buf, sizeof buf, "%s/rapt/r-pkg/R/manager.R", home);
            path = buf;
        }
    }
    FILE *f = path ? fopen(path, "rb") : NULL;
    if (f == NULL) {
        printf("rapt source not found (%s); skipping cross-repo drift check\n",
               path ? path : "unset");
        return 0;
    }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *src = malloc((size_t) sz + 1);
    if (src == NULL) {
        fclose(f);
        return 2;
    }
    size_t got = fread(src, 1, (size_t) sz, f);
    src[got] = '\0';
    fclose(f);

    int found = strstr(src, PINNED) != NULL;
    free(src);
    if (found) {
        printf("ok: rapt r-pkg/R/manager.R still pins %s\n", PINNED);
        return 0;
    }
    fprintf(stderr, "FAIL: pinned predicate %s not found in %s (rapt drift)\n",
            PINNED, path);
    return 1;
}
