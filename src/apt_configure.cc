/* D. configure effector (apt.configure): finish the pending-configuration set
 * with `dpkg --configure --pending` (through the hardened no-shell spawn helper).
 * Enumerates the packages left unconfigured (unpacked / half-configured /
 * triggers pending-or-awaited), spends the receipt, and — only on a validated
 * redeem_ok — runs the configure pass. No dep resolve, no pkgAcquire.
 *
 * Ownership still applies (plan §4D): the pending set is not selectable, but
 * configuring an r-* package runs its maintainer scripts — so a rapt-owned member
 * is refused in the plan step before the receipt is spent. The write is reached
 * solely through pkgx_effect_gate.
 *
 * configure DOES run dpkg and can leave the database half-applied, so its ground
 * truth is the SAME incomplete-state scan A uses (apt_common:
 * pkgx_apt_ground_truth_broken) — the scan plan §4D and codex both point here.
 * With no fetch phase, execution begins the moment the gate admits, so the shared
 * pkgx_txn_classify decides OK / COMMIT_FAILED / BROKEN over that scan.
 * VM-runtime; CI links it as part of the mutation-path proof. See apt_effect.hh. */
#include "apt_common.hh"
#include "apt_effect.hh"

#include "apt_status.h"
#include "digest.h"
#include "effect.h"
#include "plan.h"
#include "result.h"
#include "spawn.h"
#include "transport.h"

#include <apt-pkg/cachefile.h>
#include <apt-pkg/configuration.h>
#include <apt-pkg/pkgcache.h>
#include <apt-pkg/pkgsystem.h>

#include <deque>
#include <string>
#include <vector>

namespace {

/* The pending-configuration states `dpkg --configure --pending` acts on, and
 * their descriptor names. HalfInstalled (an interrupted unpack) is NOT one of
 * them: --configure --pending cannot repair it (it needs re-unpack), so it is not
 * a configure target — it is an observed blocker, handled before redemption as a
 * pre-commit BROKEN refusal (below), never encoded into the configure descriptor. */
const char *pending_state(unsigned char cur) {
    switch (cur) {
    case pkgCache::State::UnPacked:
        return "unpacked";
    case pkgCache::State::HalfConfigured:
        return "half-configured";
    case pkgCache::State::TriggersAwaited:
        return "triggers-awaited";
    case pkgCache::State::TriggersPending:
        return "triggers-pending";
    default:
        return nullptr; /* not part of the configure pass */
    }
}

/* Stable storage for the configure records; the C records borrow these. */
struct CfgHolder {
    std::string package, arch, version, state;
};

struct ConfigureCommitCtx {
    std::string dpkg; /* apt-configured dpkg path (kept alive for argv) */
    bool entered;
    bool issued; /* the dpkg child was spawned (effect_issued) */
    bool ran_ok;
};

/* pkgx_committer: run the pending-config pass. Invoked ONLY by the gate. */
extern "C" int configure_commit(void *ctx, const char *correlation_id) {
    (void) correlation_id; /* the shelled dpkg writes no apt history record to stamp */
    ConfigureCommitCtx *c = static_cast<ConfigureCommitCtx *>(ctx);
    c->entered = true;
    /* Hand the inner dpkg database lock to the child (release it, keep the outer
     * frontend lock held), as DoInstall does for A; otherwise the spawned dpkg
     * blocks on the lock we still hold. The child is additionally given
     * DPKG_FRONTEND_LOCKED=true so it skips the frontend lock we keep and takes only
     * the inner lock we released — child-only, never in this process's environment.
     * If the hand-off fails, do not run dpkg (effect not issued). */
    if (!_system->UnLockInner()) {
        return -1;
    }
    static const char *const frontend_locked[] = {"DPKG_FRONTEND_LOCKED=true",
                                                  nullptr};
    const char *argv[] = {c->dpkg.c_str(), "--configure", "--pending", nullptr};
    int started = 0;
    c->ran_ok = (pkgx_spawn_wait_env(argv, nullptr, frontend_locked, &started) == 0);
    c->issued = (started != 0); /* effect_issued: dpkg ran, so state may have changed */
    /* Re-take the inner lock under the still-held outer lock; a failure leaves the
     * context inconsistent, so fail closed and let the caller reconcile. */
    if (!_system->LockInner()) {
        c->ran_ok = false;
    }
    return c->ran_ok ? 0 : -1;
}

} /* namespace */

extern "C" pkgx_apt_status pkgx_apt_configure_effect(
    const char *effect_receipt, uid_t principal_uid, int plan_schema,
    const char *expected_cid, int lock_timeout_s, pkgx_transport *tx,
    char out_cid[PKGX_CID_LEN + 1], int *effect_issued, char *detail) {
    pkgx_detail_set(detail, "");
    *effect_issued = 0; /* stays 0 through the half-installed refusal and any
                         * pre-spawn failure; set only once dpkg is spawned */
    const char *err = nullptr;
    if (!pkgx_apt_init(&err)) {
        pkgx_detail_set(detail, err);
        return PKGX_APT_INTERNAL;
    }
    pkgx_apt_set_lock_timeout(lock_timeout_s);

    /* Frontend lock first (contention is retryable); then read the cache without
     * re-locking, so a failure there is a cache fault, not a lock timeout. */
    if (!_system->Lock()) {
        pkgx_detail_set(detail, "apt_locked");
        return PKGX_APT_LOCKED;
    }
    pkgCacheFile cache;
    if (!cache.Open(nullptr, false)) {
        pkgx_detail_set(detail, "cache");
        return PKGX_APT_INTERNAL;
    }
    pkgCache *c = cache.GetPkgCache();
    if (c == nullptr) {
        pkgx_detail_set(detail, "cache");
        return PKGX_APT_INTERNAL;
    }

    /* Enumerate the pending-configuration set from the current dpkg states. A
     * half-installed package (interrupted unpack) is unrepairable by configure:
     * the system is already broken in a way this verb will not fix, so refuse
     * with BROKEN before the receipt is spent — the caller must resolve the
     * half-installed package first. Copy the name into the caller buffer (it
     * borrows the cache, destroyed on return). */
    std::deque<CfgHolder> holders;
    for (pkgCache::PkgIterator P = c->PkgBegin(); !P.end(); ++P) {
        if (P->CurrentState == pkgCache::State::HalfInstalled) {
            pkgx_detail_set(detail, P.Name());
            return PKGX_APT_BROKEN;
        }
        const char *state = pending_state(P->CurrentState);
        if (state == nullptr) {
            continue;
        }
        CfgHolder h;
        h.package = P.Name();
        h.arch = P.Arch();
        pkgCache::VerIterator cur = P.CurrentVer();
        h.version = cur.end() ? "" : cur.VerStr();
        h.state = state;
        holders.push_back(std::move(h));
    }

    std::vector<pkgx_cfg_record> cfgs;
    for (auto &h : holders) {
        pkgx_cfg_record r;
        r.package = h.package.c_str();
        r.architecture = h.arch.c_str();
        r.current_version = h.version.c_str();
        r.state = h.state.c_str();
        cfgs.push_back(r);
    }

    /* The offending package (ownership refusal) borrows the `holders` deque, so
     * snapshot the plan detail into the caller buffer while that deque is alive. */
    const char *pdetail = "";
    pkgx_plan_result pr = pkgx_plan_and_redeem_configure(
        cfgs.data(), cfgs.size(), effect_receipt, principal_uid, plan_schema,
        expected_cid, pkgx_transport_tx, tx, out_cid, &pdetail);
    pkgx_detail_set(detail, pdetail);

    switch (pr) {
    case PKGX_PLAN_NO_OP:
        return PKGX_APT_NO_OP;
    case PKGX_PLAN_NOT_OWNED:
        return PKGX_APT_NOT_OWNED;
    case PKGX_PLAN_HELD:
        return PKGX_APT_HELD; /* unreachable: configure has no held-package policy */
    case PKGX_PLAN_PROTECTED:
        return PKGX_APT_PROTECTED; /* unreachable: no protection policy */
    case PKGX_PLAN_NO_INTENT:
        return PKGX_APT_NO_INTENT;
    case PKGX_PLAN_INTERNAL:
        return PKGX_APT_INTERNAL;
    case PKGX_PLAN_OK:
        break;
    }

    ConfigureCommitCtx cc;
    cc.dpkg = _config->Find("Dir::Bin::dpkg", "/usr/bin/dpkg");
    cc.entered = false;
    cc.issued = false;
    cc.ran_ok = false;
    pkgx_effect_gate(pr, out_cid, configure_commit, &cc);

    /* effect_issued tracks the actual dpkg spawn; the classifier's execution_began
     * stays `entered` so a pending set left incomplete (e.g. the lock hand-off
     * failed before dpkg ran) is still reported BROKEN via the scan, not masked as
     * not-applied. configure has no fetch phase, so entering means dpkg is
     * attempted; read the shared ground truth once it did. */
    *effect_issued = cc.issued ? 1 : 0;
    int broken = cc.entered ? (pkgx_apt_ground_truth_broken() ? 1 : 0) : 0;
    pkgx_apt_status st = pkgx_txn_classify(cc.entered, cc.entered ? 1 : 0,
                                           cc.ran_ok ? 1 : 0, broken);
    switch (st) {
    case PKGX_APT_OK:
        pkgx_detail_set(detail, "ok");
        break;
    case PKGX_APT_BROKEN:
        pkgx_detail_set(detail, "broken");
        break;
    case PKGX_APT_COMMIT_FAILED:
        pkgx_detail_set(detail, "configure");
        break;
    default:
        pkgx_detail_set(detail, "internal");
        break;
    }
    return st;
}
