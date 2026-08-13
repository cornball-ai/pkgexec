/* A. Package-transaction effector (install/remove/purge/upgrade/dist_upgrade).
 * Opens the locked cache, resolves the transaction, spends the receipt, and —
 * only on a validated redeem_ok — runs GetArchives + DoInstall on that SAME
 * locked cache. The committer is reached solely through pkgx_effect_gate, so a
 * refused or unredeemed plan cannot fetch or install anything.
 *
 * After the attempt the true outcome is read from a FRESH cache (dpkg ground
 * truth), not the stale pre-commit dep cache, and classified by
 * pkgx_txn_classify: a pre-effect failure (fetch/setup, host untouched) is
 * distinct from a dpkg run that left the database broken. VM-runtime; CI links
 * it as the mutation-path proof. See apt_effect.hh. */
#include "apt_common.hh"
#include "apt_effect.hh"

#include "apt_status.h"
#include "digest.h"
#include "effect.h"
#include "plan.h"
#include "transport.h"

#include <apt-pkg/acquire.h>
#include <apt-pkg/algorithms.h>
#include <apt-pkg/cachefile.h>
#include <apt-pkg/configuration.h>
#include <apt-pkg/depcache.h>
#include <apt-pkg/error.h>
#include <apt-pkg/init.h>
#include <apt-pkg/install-progress.h>
#include <apt-pkg/packagemanager.h>
#include <apt-pkg/pkgcache.h>
#include <apt-pkg/pkgrecords.h>
#include <apt-pkg/pkgsystem.h>
#include <apt-pkg/sourcelist.h>
#include <apt-pkg/upgrade.h>

#include <cstring>
#include <deque>
#include <memory>
#include <string>
#include <vector>

namespace {

/* The retained context handed to the committer: the very cache whose resolved
 * state produced the redeemed plan_hash, plus a record of how far execution got
 * (so the effector can tell a pre-effect failure from a partial dpkg run). */
struct TxnCommitCtx {
    pkgCacheFile *cache;
    bool entered;         /* the committer body ran (gate admitted the commit) */
    bool fetched;         /* GetArchives + fetcher.Run() succeeded */
    bool execution_began; /* DoInstall was invoked — dpkg actually ran */
    bool committed_ok;    /* DoInstall returned Completed */
};

/* pkgx_committer: fetch the archives and run the dpkg transaction on the
 * retained cache. Invoked ONLY by the gate, i.e. after a validated redeem_ok. */
extern "C" int txn_commit(void *ctx, const char *correlation_id) {
    TxnCommitCtx *c = static_cast<TxnCommitCtx *>(ctx);
    c->entered = true;
    pkgCacheFile &cache = *c->cache;

    /* Stamp the correlation id for apt's native transaction record. The probe
     * proved this config slot round-trips; its emission into history.log is
     * validated on the VM. */
    std::string marker = std::string("runix:") + (correlation_id ? correlation_id : "");
    _config->Set("CommandLine::AsString", marker);

    pkgDepCache *dc = cache.GetDepCache();
    pkgCache *pc = cache.GetPkgCache();
    pkgSourceList *sources = cache.GetSourceList();
    if (dc == nullptr || pc == nullptr || sources == nullptr) {
        return -1;
    }
    std::unique_ptr<pkgPackageManager> pm(_system->CreatePM(dc));
    if (!pm) {
        return -1;
    }
    pkgRecords records(*pc);
    if (_error->PendingError()) {
        return -1;
    }
    PkgxQuietAcquireStatus status;
    pkgAcquire fetcher(&status);
    if (!pm->GetArchives(&fetcher, sources, &records)) {
        return -1;
    }
    if (fetcher.Run() != pkgAcquire::Continue) {
        return -1; /* archive fetch failed: nothing has been applied yet */
    }
    c->fetched = true;

    std::unique_ptr<APT::Progress::PackageManager> progress(
        APT::Progress::PackageManagerProgressFactory());
    c->execution_began = true; /* from here the host may be mutated */
    pkgPackageManager::OrderResult res = pm->DoInstall(progress.get());
    c->committed_ok = (res == pkgPackageManager::Completed);
    return c->committed_ok ? 0 : -1;
}

/* dpkg ground truth after the transaction is the shared fresh-cache scan
 * (apt_common: pkgx_apt_ground_truth_broken) — the pre-commit dep cache is stale,
 * so the true post-effect state is read from a fresh cache. Configure (D) reads
 * the same scan; A and D are the two dpkg-running mechanisms. */

} /* namespace */

extern "C" pkgx_apt_status pkgx_apt_txn_effect(
    const char *verb, const char *const *targets, size_t ntargets,
    const char *effect_receipt, uid_t principal_uid, int plan_schema,
    const char *expected_cid, int lock_timeout_s, pkgx_transport *tx,
    char out_cid[PKGX_CID_LEN + 1], const char **detail) {
    *detail = "";
    const char *err = nullptr;
    if (!pkgx_apt_init(&err)) {
        *detail = err;
        return PKGX_APT_INTERNAL;
    }
    pkgx_apt_set_lock_timeout(lock_timeout_s);

    const bool removal =
        (std::strcmp(verb, "apt.remove") == 0 || std::strcmp(verb, "apt.purge") == 0);
    const bool purge = (std::strcmp(verb, "apt.purge") == 0);
    const bool upgrade = (std::strcmp(verb, "apt.upgrade") == 0);
    const bool dist = (std::strcmp(verb, "apt.dist_upgrade") == 0);

    /* v1: upgrade/dist-upgrade are whole-system; the parser rejects targets for
     * them, and this guards the effector directly (belt and suspenders). */
    if ((upgrade || dist) && ntargets != 0) {
        *detail = "targets_unsupported";
        return PKGX_APT_RESOLVE_FAILED;
    }

    /* Acquire the dpkg frontend lock first, honoring the timeout — a miss here is
     * genuine contention. Then build the cache WITHOUT re-locking, so a failure
     * there is a cache/configuration fault, not a lock timeout. */
    if (!_system->Lock()) {
        *detail = "apt_locked";
        return PKGX_APT_LOCKED;
    }
    pkgCacheFile cache;
    if (!cache.Open(nullptr, false)) {
        *detail = "cache";
        return PKGX_APT_INTERNAL;
    }
    pkgCache *c = cache.GetPkgCache();
    pkgDepCache *dc = cache.GetDepCache();
    if (c == nullptr || dc == nullptr) {
        *detail = "cache";
        return PKGX_APT_INTERNAL;
    }

    if (upgrade || dist) {
        const int mode =
            dist ? APT::Upgrade::ALLOW_EVERYTHING : APT::Upgrade::FORBID_REMOVE_PACKAGES;
        if (!APT::Upgrade::Upgrade(*dc, mode)) {
            *detail = "resolve";
            return PKGX_APT_RESOLVE_FAILED;
        }
    } else {
        pkgProblemResolver resolver(dc);
        for (size_t i = 0; i < ntargets; i++) {
            pkgCache::PkgIterator P = c->FindPkg(targets[i]);
            if (P.end()) {
                *detail = targets[i]; /* unknown package */
                return PKGX_APT_RESOLVE_FAILED;
            }
            resolver.Protect(P);
            if (removal) {
                dc->MarkDelete(P, purge);
                resolver.Remove(P);
            } else {
                dc->MarkInstall(P, true);
            }
        }
        if (!resolver.Resolve(true)) {
            *detail = "resolve";
            return PKGX_APT_RESOLVE_FAILED;
        }
    }

    /* Map the resolved transaction to the digest's record model — the whole
     * transaction (target + every pulled dependency). */
    std::deque<PkgxHolder> holders;
    std::vector<pkgx_txn_record> recs;
    pkgx_apt_map_txn(c, dc, holders, recs);

    /* Policy, resource, digest, redeem — over the resolved records. */
    pkgx_plan_result pr = pkgx_plan_and_redeem(
        verb, recs.data(), recs.size(), targets, ntargets, effect_receipt,
        principal_uid, plan_schema, expected_cid, pkgx_transport_tx, tx, out_cid,
        detail);

    switch (pr) {
    case PKGX_PLAN_NO_OP:
        return PKGX_APT_NO_OP;
    case PKGX_PLAN_NOT_OWNED:
        return PKGX_APT_NOT_OWNED;
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

    /* Commit only through the gate, in the retained (still-locked) context. */
    TxnCommitCtx cc = {&cache, false, false, false, false};
    pkgx_effect_gate(pr, out_cid, txn_commit, &cc);

    /* Read dpkg ground truth after the attempt — success OR failure — but only
     * once execution actually began (else the fresh read reflects no change). */
    int broken = 0;
    if (cc.execution_began) {
        broken = pkgx_apt_ground_truth_broken() ? 1 : 0;
    }
    pkgx_apt_status st = pkgx_txn_classify(cc.entered, cc.execution_began,
                                           cc.committed_ok, broken);
    switch (st) {
    case PKGX_APT_OK:
        *detail = "ok";
        break;
    case PKGX_APT_NOT_APPLIED:
        *detail = cc.fetched ? "commit_setup" : "fetch";
        break;
    case PKGX_APT_BROKEN:
        *detail = "broken";
        break;
    case PKGX_APT_COMMIT_FAILED:
        *detail = "commit";
        break;
    default:
        *detail = "internal";
        break;
    }
    return st;
}
