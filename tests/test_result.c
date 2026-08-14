/* pkgx_result_json + pkgx_status_name: the strict result channel. effect_issued
 * must be a JSON boolean, carried independently of the status (the whole point —
 * an honest "was the host touched?" that status alone cannot reconstruct). Parses
 * the output back with Jansson so the assertions are structural, not byte-brittle.
 * Pure; no libapt, no root. ASan/UBSan. */
#include "../src/apt_status.h"
#include "../src/result.h"

#include <jansson.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
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

/* Encode, parse back, and return the parsed object (or NULL on encode failure). */
static json_t *roundtrip(pkgx_apt_status st, int issued, const char *cid,
                         const char *detail) {
    char buf[512];
    int n = pkgx_result_json(st, issued, cid, detail, buf, sizeof buf);
    if (n < 0) {
        return NULL;
    }
    if ((size_t) n != strlen(buf)) {
        return NULL;
    }
    json_error_t err;
    return json_loads(buf, 0, &err);
}

static int is_bool_eq(json_t *o, const char *key, int want_true) {
    json_t *v = json_object_get(o, key);
    if (v == NULL || !json_is_boolean(v)) {
        return 0; /* must be a real JSON boolean, not 0/1/"true" */
    }
    return json_is_true(v) == (want_true ? 1 : 0);
}

static int is_str_eq(json_t *o, const char *key, const char *want) {
    json_t *v = json_object_get(o, key);
    return v != NULL && json_is_string(v) &&
           strcmp(json_string_value(v), want) == 0;
}

int main(void) {
    /* --- status name map --- */
    CHECK(strcmp(pkgx_status_name(PKGX_APT_OK), "ok") == 0, "name: ok");
    CHECK(strcmp(pkgx_status_name(PKGX_APT_NO_OP), "no_op") == 0, "name: no_op");
    CHECK(strcmp(pkgx_status_name(PKGX_APT_LOCKED), "apt_locked") == 0,
          "name: apt_locked");
    CHECK(strcmp(pkgx_status_name(PKGX_APT_NOT_OWNED), "package_not_owned") == 0,
          "name: package_not_owned");
    CHECK(strcmp(pkgx_status_name(PKGX_APT_HELD), "held") == 0, "name: held");
    CHECK(strcmp(pkgx_status_name(PKGX_APT_PROTECTED), "protected_package") == 0,
          "name: protected_package");
    CHECK(strcmp(pkgx_status_name(PKGX_APT_NO_INTENT), "no_intent") == 0,
          "name: no_intent");
    CHECK(strcmp(pkgx_status_name(PKGX_APT_RESOLVE_FAILED), "resolve_failed") == 0,
          "name: resolve_failed");
    CHECK(strcmp(pkgx_status_name(PKGX_APT_NOT_APPLIED), "not_applied") == 0,
          "name: not_applied");
    CHECK(strcmp(pkgx_status_name(PKGX_APT_COMMIT_FAILED), "operation_failed") == 0,
          "name: operation_failed");
    CHECK(strcmp(pkgx_status_name(PKGX_APT_BROKEN), "dpkg_broken") == 0,
          "name: dpkg_broken");
    CHECK(strcmp(pkgx_status_name(PKGX_APT_INTERNAL), "internal") == 0,
          "name: internal");

    /* --- ok + effect issued --- */
    json_t *o = roundtrip(PKGX_APT_OK, 1, "20250101000000000000-0123456789abcdef",
                          "ok");
    CHECK(o != NULL, "ok: encodes");
    if (o != NULL) {
        CHECK(is_str_eq(o, "status", "ok"), "ok: status");
        CHECK(is_bool_eq(o, "effect_issued", 1), "ok: effect_issued true (bool)");
        CHECK(is_str_eq(o, "correlation_id",
                        "20250101000000000000-0123456789abcdef"),
              "ok: correlation_id");
        CHECK(is_str_eq(o, "detail", "ok"), "ok: detail");
        json_decref(o);
    }

    /* --- dpkg_broken but effect WAS issued: the interrupted-dpkg audit case.
     * status != ok, yet the host was touched, so effect_issued must be true. --- */
    o = roundtrip(PKGX_APT_BROKEN, 1, "20250101000000000000-0123456789abcdef",
                  "broken");
    CHECK(o != NULL, "broken: encodes");
    if (o != NULL) {
        CHECK(is_str_eq(o, "status", "dpkg_broken"), "broken: status");
        CHECK(is_bool_eq(o, "effect_issued", 1),
              "broken: effect_issued true (host was touched)");
        json_decref(o);
    }

    /* --- dpkg_broken and effect NOT issued: the half-installed pre-redeem refusal.
     * status is broken (system found broken), but WE issued nothing. --- */
    o = roundtrip(PKGX_APT_BROKEN, 0, "", "half-installed-pkg");
    CHECK(o != NULL, "half-installed: encodes");
    if (o != NULL) {
        CHECK(is_str_eq(o, "status", "dpkg_broken"), "half-installed: status");
        CHECK(is_bool_eq(o, "effect_issued", 0),
              "half-installed: effect_issued false (nothing ran)");
        CHECK(is_str_eq(o, "correlation_id", ""), "half-installed: empty cid ok");
        json_decref(o);
    }

    /* --- no_intent never issues an effect --- */
    o = roundtrip(PKGX_APT_NO_INTENT, 0, "", "refused");
    CHECK(o != NULL, "no_intent: encodes");
    if (o != NULL) {
        CHECK(is_bool_eq(o, "effect_issued", 0), "no_intent: effect_issued false");
        json_decref(o);
    }

    /* --- NULL cid/detail serialize as "" --- */
    o = roundtrip(PKGX_APT_INTERNAL, 0, NULL, NULL);
    CHECK(o != NULL, "null fields: encodes");
    if (o != NULL) {
        CHECK(is_str_eq(o, "correlation_id", ""), "null cid -> \"\"");
        CHECK(is_str_eq(o, "detail", ""), "null detail -> \"\"");
        json_decref(o);
    }

    /* --- buffer too small: fail-closed, out untouched --- */
    char tiny[8];
    memset(tiny, 'Z', sizeof tiny);
    int n = pkgx_result_json(PKGX_APT_OK, 1, "x", "y", tiny, sizeof tiny);
    CHECK(n < 0, "tiny buffer -> -1");
    CHECK(tiny[0] == 'Z', "tiny buffer: out untouched on failure");

    /* --- pkgx_result_emit writes the record + newline in full --- */
    int pfd[2];
    if (pipe(pfd) == 0) {
        int rc = pkgx_result_emit(pfd[1], PKGX_APT_OK, 1, "cid", "ok");
        close(pfd[1]);
        CHECK(rc == 0, "emit: full write to an open pipe -> 0");
        char rbuf[512];
        ssize_t got = read(pfd[0], rbuf, sizeof rbuf - 1);
        close(pfd[0]);
        CHECK(got > 1, "emit: record read back");
        if (got > 1) {
            CHECK(rbuf[got - 1] == '\n', "emit: trailing newline");
            rbuf[got - 1] = '\0'; /* drop newline, parse the JSON */
            json_error_t err;
            json_t *o2 = json_loads(rbuf, 0, &err);
            CHECK(o2 != NULL, "emit: payload is valid JSON");
            if (o2 != NULL) {
                CHECK(is_bool_eq(o2, "effect_issued", 1),
                      "emit: effect_issued carried");
                json_decref(o2);
            }
        }
    }

    /* --- emit to a closed result pipe fails (never a silent success), and the
     * SIGPIPE that a naive write would raise must NOT kill this process. --- */
    int cfd[2];
    if (pipe(cfd) == 0) {
        close(cfd[0]); /* reader gone */
        int rc = pkgx_result_emit(cfd[1], PKGX_APT_OK, 0, "", "ok");
        close(cfd[1]);
        CHECK(rc == -1, "emit: closed pipe -> -1, process survived");
    }

    /* --- result-channel isolation: an effector/dpkg writing garbage to stdout must
     * NOT reach the protocol channel. In a child, wire fd1->respipe and fd2->errpipe,
     * open the result channel (dups fd1 to a CLOEXEC result fd, redirects fd1 to fd2),
     * splatter garbage on fd1/stdio, then emit ONE result to the dedicated fd. The
     * respipe must carry exactly one valid JSON object; the garbage lands on fd2. --- */
    int rp[2], ep[2];
    if (pipe(rp) == 0 && pipe(ep) == 0) {
        pid_t pid = fork();
        if (pid == 0) {
            if (dup2(rp[1], STDOUT_FILENO) < 0 || dup2(ep[1], STDERR_FILENO) < 0) {
                _exit(2);
            }
            close(rp[0]);
            close(rp[1]);
            close(ep[0]);
            close(ep[1]);
            int rfd = pkgx_result_channel_open(); /* fd1 now points at the err pipe */
            if (rfd < 0) {
                _exit(3);
            }
            const char *g = "Unpacking canary (1.0)...\nSetting up canary...\n{bad\n";
            (void) !write(STDOUT_FILENO, g, strlen(g)); /* raw write to fd1 */
            printf("buffered stdio garbage\n");         /* stdio to fd1 */
            fflush(stdout);
            pkgx_result_emit(rfd, PKGX_APT_OK, 1,
                             "20250101000000000000-0123456789abcdef", "ok");
            _exit(0);
        }
        close(rp[1]);
        close(ep[1]);
        char resbuf[2048];
        size_t rn = 0;
        ssize_t t;
        while (rn < sizeof resbuf - 1 &&
               (t = read(rp[0], resbuf + rn, sizeof resbuf - 1 - rn)) > 0) {
            rn += (size_t) t;
        }
        resbuf[rn] = '\0';
        close(rp[0]);
        char errbuf[2048];
        size_t en = 0;
        while (en < sizeof errbuf - 1 &&
               (t = read(ep[0], errbuf + en, sizeof errbuf - 1 - en)) > 0) {
            en += (size_t) t;
        }
        errbuf[en] = '\0';
        close(ep[0]);
        int cst = 0;
        waitpid(pid, &cst, 0);
        int nl = 0;
        for (size_t i = 0; i < rn; i++) {
            if (resbuf[i] == '\n') {
                nl++;
            }
        }
        CHECK(nl == 1 && rn > 1 && resbuf[rn - 1] == '\n',
              "isolate: exactly one line on the result channel");
        CHECK(strstr(resbuf, "Unpacking") == NULL && strstr(resbuf, "Setting up") == NULL,
              "isolate: no commit garbage on the result channel");
        if (rn > 0) {
            resbuf[rn - 1] = '\0'; /* drop newline, parse */
            json_error_t ierr;
            json_t *io = json_loads(resbuf, 0, &ierr);
            CHECK(io != NULL, "isolate: result channel is one valid JSON object");
            if (io != NULL) {
                CHECK(is_str_eq(io, "status", "ok"), "isolate: status ok");
                CHECK(is_bool_eq(io, "effect_issued", 1), "isolate: effect_issued true");
                json_decref(io);
            }
        }
        CHECK(strstr(errbuf, "Unpacking") != NULL,
              "isolate: commit garbage was diverted to stderr");
    }

    printf("%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
