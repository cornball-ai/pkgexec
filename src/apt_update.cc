/* B. update effector (apt.update): a source-list refresh. Reads the configured
 * sources into the schema-1 source records, spends the receipt, and — only on a
 * validated redeem_ok — runs ListUpdate over that SAME source list. No dep
 * resolve, no dpkg, so no package policy and no broken-state check (a refresh
 * cannot leave the dpkg database half-applied). The commit is reached solely
 * through pkgx_effect_gate, so a refused or unredeemed plan refreshes nothing.
 *
 * Ground truth is update's own, not A's dpkg scan (plan §4B): the ListUpdate
 * result AND a fresh cache that re-opens over the rebuilt indexes. VM-runtime; CI
 * links it as part of the mutation-path proof. See apt_effect.hh. */
#include "apt_common.hh"
#include "apt_effect.hh"

#include "apt_status.h"
#include "digest.h"
#include "effect.h"
#include "plan.h"
#include "result.h"
#include "transport.h"

#include <apt-pkg/cachefile.h>
#include <apt-pkg/configuration.h>
#include <apt-pkg/error.h>
#include <apt-pkg/fileutl.h>
#include <apt-pkg/pkgcache.h>
#include <apt-pkg/sourcelist.h>
#include <apt-pkg/update.h>

#include <string>
#include <unistd.h>
#include <vector>

namespace {

/* The retained context: the very source list that was digested is the list
 * ListUpdate refreshes (the digested plan is the committed plan). */
struct UpdateCommitCtx {
    pkgSourceList *list;
    PkgxQuietAcquireStatus *status;
    bool entered;
    bool refresh_ok;
};

/* pkgx_committer: refresh the indexes for the retained source list. Invoked ONLY
 * by the gate, i.e. after a validated redeem_ok. */
extern "C" int update_commit(void *ctx, const char *correlation_id) {
    (void) correlation_id; /* update writes no dpkg history record to stamp */
    UpdateCommitCtx *c = static_cast<UpdateCommitCtx *>(ctx);
    c->entered = true;
    c->refresh_ok = ListUpdate(*c->status, *c->list);
    return c->refresh_ok ? 0 : -1;
}

/* Update's ground truth for "indexes readable": a fresh cache re-opens over the
 * refreshed lists and yields a package cache. Isolated from the refresh's error
 * stack; an unreadable cache is reported as not-readable (fail-safe). */
bool indexes_readable() {
    _error->PushToStack();
    bool ok = false;
    pkgCacheFile fresh;
    if (fresh.Open(nullptr, false)) {
        ok = (fresh.GetPkgCache() != nullptr);
    }
    _error->RevertToStack();
    return ok;
}

} /* namespace */

extern "C" pkgx_apt_status pkgx_apt_update_effect(
    const char *resource_token, const char *effect_receipt, uid_t principal_uid,
    int plan_schema, const char *expected_cid, int lock_timeout_s,
    pkgx_transport *tx, char out_cid[PKGX_CID_LEN + 1], int *effect_issued,
    char *detail) {
    pkgx_detail_set(detail, "");
    *effect_issued = 0; /* nothing issued until ListUpdate begins */
    const char *err = nullptr;
    if (!pkgx_apt_init(&err)) {
        pkgx_detail_set(detail, err);
        return PKGX_APT_INTERNAL;
    }
    pkgx_apt_set_lock_timeout(lock_timeout_s);

    /* v1: update is whole-source-list only. A nonempty resource_token would name
     * a subset, but ListUpdate always refreshes the ENTIRE retained source list,
     * so a subset request cannot be honored faithfully — reject it before locking
     * (as targeted upgrades are rejected) until subset execution exists. */
    if (resource_token != nullptr && resource_token[0] != '\0') {
        pkgx_detail_set(detail, "subset_unsupported");
        return PKGX_APT_RESOLVE_FAILED;
    }

    /* Update takes the lists lock, not the dpkg frontend lock (plan §4B).
     * ListUpdate acquires it internally, so probe it non-blocking first to
     * surface genuine contention as a retryable lock miss, then release: holding
     * it here would make ListUpdate's own acquisition fail. The small window
     * between release and re-acquire only downgrades a contended lock to an
     * operation failure, never a false success. */
    std::string lock_path = _config->FindDir("Dir::State::Lists") + "lock";
    int lfd = GetLock(lock_path, false);
    if (lfd < 0) {
        pkgx_detail_set(detail, "apt_locked");
        return PKGX_APT_LOCKED;
    }
    close(lfd);

    pkgSourceList list;
    if (!list.ReadMainList()) {
        pkgx_detail_set(detail, "sources");
        return PKGX_APT_INTERNAL;
    }

    /* Fail the refresh on ANY source error, not just a total failure: a partial
     * fetch failure otherwise leaves stale-but-readable indexes that would pass a
     * plain readability check and look like success. With Error-Mode=any,
     * ListUpdate returns false if any configured source fails, so a partial
     * refresh is COMMIT_FAILED, not OK. */
    _config->Set("APT::Update::Error-Mode", "any");

    /* Enumerate the configured sources into the schema-1 source records via the
     * shared builder (the same one the read-only planner uses), so preview and commit
     * derive an identical digest from one code path. */
    std::deque<PkgxSrcHolder> holders;
    std::vector<pkgx_src_record> recs;
    pkgx_apt_map_sources(list, holders, recs);

    /* update has no package policy, so the plan detail here is only a redeem code
     * (stable), but snapshot uniformly into the caller buffer all the same. */
    const char *pdetail = "";
    pkgx_plan_result pr = pkgx_plan_and_redeem_update(
        recs.data(), recs.size(), resource_token, effect_receipt, principal_uid,
        plan_schema, expected_cid, pkgx_transport_tx, tx, out_cid, &pdetail);
    pkgx_detail_set(detail, pdetail);

    switch (pr) {
    case PKGX_PLAN_NO_OP:
        return PKGX_APT_NO_OP;
    case PKGX_PLAN_NOT_OWNED:
        return PKGX_APT_NOT_OWNED; /* unreachable: a refresh has no package policy */
    case PKGX_PLAN_HELD:
        return PKGX_APT_HELD;
    case PKGX_PLAN_PROTECTED:
        return PKGX_APT_PROTECTED;
    case PKGX_PLAN_NO_INTENT:
        return PKGX_APT_NO_INTENT;
    case PKGX_PLAN_INTERNAL:
        return PKGX_APT_INTERNAL;
    case PKGX_PLAN_OK:
        break;
    }

    PkgxQuietAcquireStatus status;
    UpdateCommitCtx cc = {&list, &status, false, false};
    pkgx_effect_gate(pr, out_cid, update_commit, &cc);

    /* effect_issued: the committer runs ListUpdate the instant it is entered, so
     * entering IS issuing the refresh (indexes may have changed). */
    *effect_issued = cc.entered ? 1 : 0;
    int readable = cc.entered ? (indexes_readable() ? 1 : 0) : 0;
    pkgx_apt_status st =
        pkgx_update_classify(cc.entered, cc.refresh_ok ? 1 : 0, readable);
    switch (st) {
    case PKGX_APT_OK:
        pkgx_detail_set(detail, "ok");
        break;
    case PKGX_APT_COMMIT_FAILED:
        pkgx_detail_set(detail, cc.refresh_ok ? "indexes_unreadable" : "refresh");
        break;
    default:
        pkgx_detail_set(detail, "internal");
        break;
    }
    return st;
}
