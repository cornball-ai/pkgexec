/* A. Package-transaction effector (install/remove/purge/upgrade/dist_upgrade).
 * Opens the locked cache, resolves the transaction, spends the receipt, and —
 * only on a validated redeem_ok — runs GetArchives + DoInstall on that SAME
 * locked cache. The committer is reached solely through pkgx_effect_gate, so a
 * refused or unredeemed plan cannot fetch or install anything. VM-runtime; CI
 * links it as the mutation-path proof. See apt_effect.hh. */
#include "apt_common.hh"
#include "apt_effect.hh"

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
 * state produced the redeemed plan_hash. */
struct TxnCommitCtx {
    pkgCacheFile *cache;
};

/* pkgx_committer: fetch the archives and run the dpkg transaction on the
 * retained cache. Invoked ONLY by the gate, i.e. after a validated redeem_ok. */
extern "C" int txn_commit(void *ctx, const char *correlation_id) {
    TxnCommitCtx *c = static_cast<TxnCommitCtx *>(ctx);
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
        return -1;
    }
    std::unique_ptr<APT::Progress::PackageManager> progress(
        APT::Progress::PackageManagerProgressFactory());
    pkgPackageManager::OrderResult res = pm->DoInstall(progress.get());
    return (res == pkgPackageManager::Completed) ? 0 : -1;
}

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

    /* Acquire the dpkg frontend lock (WithLock=true). Bounded by the lock
     * timeout set above; a miss is retryable, no effect. */
    pkgCacheFile cache;
    if (!cache.Open(nullptr, true)) {
        *detail = "apt_locked";
        return PKGX_APT_LOCKED;
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
    TxnCommitCtx cc = {&cache};
    if (pkgx_effect_gate(pr, out_cid, txn_commit, &cc) != PKGX_EFFECT_OK) {
        *detail = "commit";
        return PKGX_APT_COMMIT_FAILED;
    }
    if (dc->BrokenCount() != 0) {
        *detail = "broken";
        return PKGX_APT_BROKEN;
    }
    return PKGX_APT_OK;
}
