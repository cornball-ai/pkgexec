/* Real broker transport against fake unix-socket servers (fork'd children over
 * a pre-fork listener; no broker, no root). The two load-bearing properties:
 *
 *  1. Peer authentication happens BEFORE any byte is written: when the peer's
 *     uid is not the required one, the server observes EOF with ZERO bytes
 *     received — the on-the-wire proof that the receipt token was never sent.
 *     (Run as any uid: the mismatch case requires getuid()+1, which can never
 *     equal the real peer uid.)
 *  2. The whole exchange sits under one absolute monotonic deadline: a server
 *     that accepts and stalls cannot pin the client past its budget.
 *
 * Plus framing strictness (bad version, oversized length, truncated body) and
 * an end-to-end pkgx_redeem over the real transport. ASan/UBSan (Makefile). */
#include "../src/redeem.h"
#include "../src/transport.h"

#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
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

#define CID "00001786382512165708-a061ec02cffe1b2b"
#define RECEIPT "1b9d6bcd1e7f4a3bd2c5e8f0a4d7c9e2"
#define REDEEM_OK_BODY \
    "{\"correlation_id\":\"" CID "\",\"ok\":true,\"persisted\":true}"

typedef enum {
    SRV_OK,       /* read frame, assert it, reply framed redeem_ok */
    SRV_SILENT,   /* expect EOF with ZERO bytes (refused peer wrote nothing) */
    SRV_STALL,    /* read frame, never reply, exit after the client's budget */
    SRV_BADVER,   /* reply with version 2 */
    SRV_TOOLARGE, /* reply header claims a body over the maximum */
    SRV_TRUNC,    /* reply header claims 100 bytes, send 10, close */
    SRV_CLOSE,    /* accept, then close immediately (peer gone after auth) */
    SRV_TRICKLE   /* reply one byte at a time, slower than the client's budget */
} srv_mode;

/* ---- blocking helpers for the fake server (child process) -------------- */

static int full_read(int fd, void *buf, size_t n) {
    unsigned char *p = buf;
    size_t got = 0;
    while (got < n) {
        ssize_t r = read(fd, p + got, n - got);
        if (r < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (r == 0) {
            return 1;
        }
        got += (size_t) r;
    }
    return 0;
}

static int full_write(int fd, const void *buf, size_t n) {
    const unsigned char *p = buf;
    size_t sent = 0;
    while (sent < n) {
        ssize_t w = write(fd, p + sent, n - sent);
        if (w < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        sent += (size_t) w;
    }
    return 0;
}

static void put_hdr(unsigned char hdr[5], unsigned ver, uint32_t len) {
    hdr[0] = (unsigned char) ver;
    hdr[1] = (unsigned char) ((len >> 24) & 0xff);
    hdr[2] = (unsigned char) ((len >> 16) & 0xff);
    hdr[3] = (unsigned char) ((len >> 8) & 0xff);
    hdr[4] = (unsigned char) (len & 0xff);
}

/* Read one request frame; NULL on any framing problem. */
static char *srv_read_frame(int cfd, uint32_t *len) {
    unsigned char hdr[5];
    if (full_read(cfd, hdr, sizeof hdr) != 0 || hdr[0] != 1) {
        return NULL;
    }
    uint32_t n = ((uint32_t) hdr[1] << 24) | ((uint32_t) hdr[2] << 16) |
                 ((uint32_t) hdr[3] << 8) | (uint32_t) hdr[4];
    if (n == 0 || n > PKGX_FRAME_MAX_BODY) {
        return NULL;
    }
    char *body = malloc((size_t) n + 1);
    if (body == NULL || full_read(cfd, body, n) != 0) {
        free(body);
        return NULL;
    }
    body[n] = '\0';
    *len = n;
    return body;
}

static int srv_reply(int cfd, unsigned ver, uint32_t claim, const char *body,
                     uint32_t body_len) {
    unsigned char hdr[5];
    put_hdr(hdr, ver, claim);
    if (full_write(cfd, hdr, sizeof hdr) != 0) {
        return -1;
    }
    if (body_len > 0 && full_write(cfd, body, body_len) != 0) {
        return -1;
    }
    return 0;
}

/* The fake server body: accept exactly one connection and act out `mode`.
 * The exit status carries the server-side assertion. SIGPIPE is ignored in the
 * CHILD only (this helper writes with write()); the PARENT keeps the default
 * disposition, so the production transport's MSG_NOSIGNAL is what's under test. */
static int srv_run(int lfd, srv_mode mode) {
    signal(SIGPIPE, SIG_IGN);
    int cfd = accept(lfd, NULL, NULL);
    if (cfd < 0) {
        return 9;
    }
    if (mode == SRV_SILENT) {
        char b;
        ssize_t r = read(cfd, &b, 1);
        close(cfd);
        return (r == 0) ? 0 : 1; /* 0 = EOF with zero bytes, as required */
    }
    if (mode == SRV_CLOSE) {
        close(cfd); /* peer vanishes right after the client authenticated it */
        return 0;
    }
    uint32_t len = 0;
    char *req = srv_read_frame(cfd, &len);
    if (req == NULL) {
        close(cfd);
        return 8;
    }
    int req_ok = strstr(req, "redeem_receipt") != NULL &&
                 strstr(req, RECEIPT) != NULL;
    free(req);
    int rc = 7;
    switch (mode) {
    case SRV_OK:
        rc = (req_ok && srv_reply(cfd, 1, (uint32_t) strlen(REDEEM_OK_BODY),
                                  REDEEM_OK_BODY,
                                  (uint32_t) strlen(REDEEM_OK_BODY)) == 0)
                 ? 0
                 : 1;
        break;
    case SRV_STALL: {
        struct timespec nap = {0, 700L * 1000000L};
        nanosleep(&nap, NULL);
        rc = 0;
        break;
    }
    case SRV_BADVER:
        rc = srv_reply(cfd, 2, 2, "{}", 2) == 0 ? 0 : 1;
        break;
    case SRV_TOOLARGE:
        rc = srv_reply(cfd, 1, PKGX_FRAME_MAX_BODY + 1, NULL, 0) == 0 ? 0 : 1;
        break;
    case SRV_TRUNC:
        rc = srv_reply(cfd, 1, 100, "0123456789", 10) == 0 ? 0 : 1;
        break;
    case SRV_TRICKLE: {
        /* A well-formed redeem_ok, but dripped one byte at a time slower than
         * the client's budget: progress never stalls, yet total duration
         * exceeds the deadline. Writes may fail once the client gives up and
         * closes (SIGPIPE is ignored here); that is expected, so exit 0. */
        unsigned char frame[5 + 128];
        uint32_t blen = (uint32_t) strlen(REDEEM_OK_BODY);
        put_hdr(frame, 1, blen);
        memcpy(frame + 5, REDEEM_OK_BODY, blen);
        size_t total = 5 + blen;
        for (size_t i = 0; i < total; i++) {
            if (full_write(cfd, frame + i, 1) != 0) {
                break; /* client gave up (deadline); stop dripping */
            }
            struct timespec nap = {0, 40L * 1000000L}; /* 40 ms per byte */
            nanosleep(&nap, NULL);
        }
        rc = 0;
        break;
    }
    default:
        break;
    }
    close(cfd);
    return rc;
}

/* Bind+listen in the parent (so the client can connect with no readiness
 * race), fork the server, return its pid. */
static pid_t spawn_server(const char *path, srv_mode mode, int *out_lfd) {
    int lfd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (lfd < 0) {
        return -1;
    }
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof addr);
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof addr.sun_path, "%s", path);
    unlink(path);
    if (bind(lfd, (struct sockaddr *) &addr, sizeof addr) != 0 ||
        listen(lfd, 4) != 0) {
        close(lfd);
        return -1;
    }
    pid_t pid = fork();
    if (pid < 0) {
        close(lfd);
        return -1;
    }
    if (pid == 0) {
        _exit(srv_run(lfd, mode));
    }
    *out_lfd = lfd;
    return pid;
}

static int reap(pid_t pid) {
    int st = 0;
    if (waitpid(pid, &st, 0) != pid || !WIFEXITED(st)) {
        return -1;
    }
    return WEXITSTATUS(st);
}

static long long elapsed_ms(const struct timespec *from) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (long long) (now.tv_sec - from->tv_sec) * 1000LL +
           (long long) (now.tv_nsec - from->tv_nsec) / 1000000LL;
}

/* One transport exchange against a fake server. Returns the transport's rc;
 * *srv_rc gets the server's exit status, *t keeps err for inspection. tx_ms
 * (nullable) gets the elapsed time of the transport call ALONE — the reap of
 * the server child (e.g. the stall server's 700ms sleep) is excluded. */
static int exchange(const char *path, srv_mode mode, uid_t required_uid,
                    int timeout_ms, pkgx_transport *t, char **resp,
                    size_t *resplen, int *srv_rc, long long *tx_ms) {
    int lfd = -1;
    pid_t pid = spawn_server(path, mode, &lfd);
    if (pid < 0) {
        *srv_rc = -1;
        return -99;
    }
    memset(t, 0, sizeof *t);
    t->socket_path = path;
    t->required_peer_uid = required_uid;
    t->timeout_ms = timeout_ms;
    const char *req = "{\"type\":\"redeem_receipt\",\"effect_receipt\":\"" RECEIPT
                      "\"}";
    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    int rc = pkgx_transport_tx(t, req, strlen(req), resp, resplen);
    if (tx_ms != NULL) {
        *tx_ms = elapsed_ms(&t0);
    }
    close(lfd);
    *srv_rc = reap(pid);
    return rc;
}

int main(void) {
    /* Deliberately NOT masking SIGPIPE in the parent: the transport must survive
     * a peer close on its own (send(MSG_NOSIGNAL)). If it regressed to write(),
     * the peer-close case below would kill this process instead of failing a
     * check — which is the behaviour we want to catch. */
    char dir[] = "/tmp/pkgx-tx-XXXXXX";
    if (mkdtemp(dir) == NULL) {
        fprintf(stderr, "mkdtemp failed\n");
        return 1;
    }
    char path[128];
    pkgx_transport t;
    char *resp = NULL;
    size_t resplen = 0;
    int srv = 0;

    /* --- happy path: peer uid matches; framed round-trip --- */
    snprintf(path, sizeof path, "%s/ok.sock", dir);
    int rc =
        exchange(path, SRV_OK, getuid(), 2000, &t, &resp, &resplen, &srv, NULL);
    CHECK(rc == 0 && resp != NULL && resplen == strlen(REDEEM_OK_BODY) &&
              strcmp(resp, REDEEM_OK_BODY) == 0,
          "matching peer uid: reply body round-trips");
    CHECK(srv == 0, "server saw a well-formed request frame with the token");
    free(resp);
    resp = NULL;

    /* --- peer uid mismatch: refused BEFORE any byte is written --- */
    snprintf(path, sizeof path, "%s/deny.sock", dir);
    rc = exchange(path, SRV_SILENT, getuid() + 1, 2000, &t, &resp, &resplen,
                  &srv, NULL);
    CHECK(rc == -1 && t.err != NULL && strcmp(t.err, "peer_uid") == 0,
          "wrong peer uid -> refused with err=peer_uid");
    CHECK(srv == 0, "refused peer observed EOF with ZERO bytes (token never sent)");
    CHECK(resp == NULL, "no reply body on refusal");

    /* --- stalling server: the absolute deadline bounds the exchange --- */
    snprintf(path, sizeof path, "%s/stall.sock", dir);
    long long took = -1;
    rc = exchange(path, SRV_STALL, getuid(), 200, &t, &resp, &resplen, &srv,
                  &took);
    CHECK(rc == -1 && t.err != NULL && strcmp(t.err, "deadline") == 0,
          "stalling server -> err=deadline");
    CHECK(took >= 0 && took < 650, "deadline actually bounded the exchange");
    CHECK(srv == 0, "stall server exited cleanly");

    /* --- peer closes right after authentication: the client must SURVIVE. --
     * Reaching this assertion at all proves no SIGPIPE killed the process; the
     * transport reports an ordinary error (EPIPE on send, or EOF on read). */
    snprintf(path, sizeof path, "%s/close.sock", dir);
    rc = exchange(path, SRV_CLOSE, getuid(), 2000, &t, &resp, &resplen, &srv,
                  NULL);
    CHECK(rc == -1 && t.err != NULL &&
              (strcmp(t.err, "send") == 0 || strcmp(t.err, "frame_eof") == 0 ||
               strcmp(t.err, "recv") == 0),
          "peer close after auth -> ordinary error, process survived (MSG_NOSIGNAL)");
    CHECK(resp == NULL, "no reply body when the peer vanished");

    /* --- trickled reply: progress never stalls, but total time exceeds the
     * budget. The deadline must bound total duration, not just idle waits. --- */
    snprintf(path, sizeof path, "%s/trickle.sock", dir);
    long long ttook = -1;
    rc = exchange(path, SRV_TRICKLE, getuid(), 200, &t, &resp, &resplen, &srv,
                  &ttook);
    CHECK(rc == -1 && t.err != NULL && strcmp(t.err, "deadline") == 0,
          "trickled reply slower than the budget -> err=deadline");
    CHECK(ttook >= 0 && ttook < 650,
          "deadline bounded a continuously-progressing trickle");
    CHECK(resp == NULL, "no reply body on a trickle timeout");

    /* --- framing strictness on the reply --- */
    snprintf(path, sizeof path, "%s/badver.sock", dir);
    rc = exchange(path, SRV_BADVER, getuid(), 2000, &t, &resp, &resplen, &srv,
                  NULL);
    CHECK(rc == -1 && t.err != NULL && strcmp(t.err, "frame_version") == 0,
          "reply version != 1 -> frame_version");

    snprintf(path, sizeof path, "%s/toolarge.sock", dir);
    rc = exchange(path, SRV_TOOLARGE, getuid(), 2000, &t, &resp, &resplen, &srv,
                  NULL);
    CHECK(rc == -1 && t.err != NULL && strcmp(t.err, "frame_toolarge") == 0,
          "reply length over the maximum -> frame_toolarge");

    snprintf(path, sizeof path, "%s/trunc.sock", dir);
    rc = exchange(path, SRV_TRUNC, getuid(), 2000, &t, &resp, &resplen, &srv,
                  NULL);
    CHECK(rc == -1 && t.err != NULL && strcmp(t.err, "frame_eof") == 0,
          "truncated reply body -> frame_eof");

    /* --- connect failures and input guards (no server) --- */
    snprintf(path, sizeof path, "%s/absent.sock", dir);
    memset(&t, 0, sizeof t);
    t.socket_path = path;
    t.required_peer_uid = getuid();
    t.timeout_ms = 500;
    rc = pkgx_transport_tx(&t, "x", 1, &resp, &resplen);
    CHECK(rc == -1 && t.err != NULL && strcmp(t.err, "connect") == 0,
          "no socket at the path -> connect");

    rc = pkgx_transport_tx(&t, "x", 0, &resp, &resplen);
    CHECK(rc == -1 && t.err != NULL && strcmp(t.err, "request_size") == 0,
          "empty request refused before any socket work");

    char longpath[200];
    memset(longpath, 'a', sizeof longpath - 1);
    longpath[sizeof longpath - 1] = '\0';
    t.socket_path = longpath;
    rc = pkgx_transport_tx(&t, "x", 1, &resp, &resplen);
    CHECK(rc == -1 && t.err != NULL && strcmp(t.err, "socket_path") == 0,
          "oversized socket path refused");

    /* --- end-to-end: pkgx_redeem over the real transport --- */
    snprintf(path, sizeof path, "%s/redeem.sock", dir);
    int lfd = -1;
    pid_t pid = spawn_server(path, SRV_OK, &lfd);
    CHECK(pid > 0, "redeem server spawned");
    memset(&t, 0, sizeof t);
    t.socket_path = path;
    t.required_peer_uid = getuid();
    t.timeout_ms = 2000;
    pkgx_redeem_req rq = {RECEIPT, 1000, "apt.install", "nginx", 1,
                          "80a7a295ea0b737188f9a3e7b41a2aa9423d7a88da22b85e0f79"
                          "e5350af9a774"};
    char out_cid[PKGX_CID_LEN + 1] = {0};
    const char *code = "";
    pkgx_redeem_status st =
        pkgx_redeem(&rq, CID, pkgx_transport_tx, &t, out_cid, &code);
    CHECK(st == PKGX_REDEEM_OK && strcmp(out_cid, CID) == 0,
          "pkgx_redeem over the real transport -> OK with the validated cid");
    close(lfd);
    CHECK(reap(pid) == 0, "redeem server saw the token-addressed request");

    /* best-effort cleanup of the socket files + dir */
    const char *names[] = {"ok.sock",       "deny.sock",  "stall.sock",
                           "badver.sock",   "toolarge.sock", "trunc.sock",
                           "absent.sock",   "redeem.sock"};
    for (size_t i = 0; i < sizeof names / sizeof names[0]; i++) {
        snprintf(path, sizeof path, "%s/%s", dir, names[i]);
        unlink(path);
    }
    rmdir(dir);

    printf("%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
