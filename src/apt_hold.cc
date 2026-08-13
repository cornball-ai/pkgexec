/* C. hold / unhold effector (apt.hold, apt.unhold): a dpkg selection-state
 * change. Reads the current selections, spends the receipt, and — only on a
 * validated redeem_ok — writes the new selections with `dpkg --set-selections`
 * (through the hardened no-shell spawn helper). Ownership is the only policy
 * (never touch a rapt-owned r-* package); it is enforced in the plan step before
 * the receipt is spent. The write is reached solely through pkgx_effect_gate.
 *
 * The effector holds the apt frontend lock (_system->Lock) continuously so no
 * other apt frontend interleaves; dpkg takes the database lock itself for the
 * brief write (the frontend/db split, as in A). A selection change runs no
 * maintainer scripts, so there is no broken-state check.
 *
 * Ground truth is hold's own, not A's dpkg scan (plan §4C): the actual dpkg
 * selection, read back from a fresh cache after the write. VM-runtime; CI links
 * it as part of the mutation-path proof. See apt_effect.hh. */
#include "apt_common.hh"
#include "apt_effect.hh"

#include "apt_status.h"
#include "digest.h"
#include "effect.h"
#include "plan.h"
#include "spawn.h"
#include "transport.h"

#include <apt-pkg/cachefile.h>
#include <apt-pkg/configuration.h>
#include <apt-pkg/error.h>
#include <apt-pkg/pkgcache.h>
#include <apt-pkg/pkgsystem.h>

#include <cstring>
#include <deque>
#include <string>
#include <vector>

namespace {

/* The dpkg selection word for a target's current selection — the same tokens
 * `dpkg --set-selections` reads and writes. */
const char *selection_word(unsigned char sel) {
    switch (sel) {
    case pkgCache::State::Install:
        return "install";
    case pkgCache::State::Hold:
        return "hold";
    case pkgCache::State::DeInstall:
        return "deinstall";
    case pkgCache::State::Purge:
        return "purge";
    default:
        return "unknown";
    }
}

/* Stable storage for the changing hold records; the C records borrow these. */
struct HoldHolder {
    std::string package, from, to;
    bool want_hold; /* the intended post-write selection, for the read-back */
};

struct HoldCommitCtx {
    const std::string *payload; /* "<pkg> <selection>\n" lines for set-selections */
    std::string dpkg;           /* apt-configured dpkg path (kept alive for argv) */
    bool entered;
    bool issued; /* the dpkg child was spawned (effect_issued) */
    bool applied;
};

/* pkgx_committer: write the new selections. Invoked ONLY by the gate. */
extern "C" int hold_commit(void *ctx, const char *correlation_id) {
    (void) correlation_id; /* set-selections writes no dpkg history record to stamp */
    HoldCommitCtx *c = static_cast<HoldCommitCtx *>(ctx);
    c->entered = true;
    /* Hand the inner dpkg database lock to the child: release it while keeping the
     * outer frontend lock held (so no other apt frontend interleaves), exactly as
     * DoInstall does for A. Without this, the spawned dpkg blocks on the lock we
     * still hold. If the hand-off fails, do not run dpkg (effect not issued). */
    if (!_system->UnLockInner()) {
        return -1;
    }
    const char *argv[] = {c->dpkg.c_str(), "--set-selections", nullptr};
    int started = 0;
    c->applied = (pkgx_spawn_wait(argv, c->payload->c_str(), &started) == 0);
    c->issued = (started != 0); /* effect_issued: dpkg ran, so state may have changed */
    /* Re-take the inner lock under the still-held outer lock; a failure leaves the
     * context inconsistent, so fail closed and let the caller reconcile. */
    if (!_system->LockInner()) {
        c->applied = false;
    }
    return c->applied ? 0 : -1;
}

/* Hold's ground truth: re-read the selection state from a fresh cache and confirm
 * every changed target now sits in its intended selection (held vs not-held).
 * Isolated from the write's error stack; an unreadable cache fails the match
 * (fail-safe). */
bool selections_match(const std::deque<HoldHolder> &changes) {
    _error->PushToStack();
    bool ok = false;
    pkgCacheFile fresh;
    if (fresh.Open(nullptr, false)) {
        pkgCache *pc = fresh.GetPkgCache();
        if (pc != nullptr) {
            ok = true;
            for (const HoldHolder &h : changes) {
                pkgCache::PkgIterator P = pc->FindPkg(h.package);
                bool is_hold =
                    !P.end() && P->SelectedState == pkgCache::State::Hold;
                if (is_hold != h.want_hold) {
                    ok = false;
                    break;
                }
            }
        }
    }
    _error->RevertToStack();
    return ok;
}

} /* namespace */

extern "C" pkgx_apt_status pkgx_apt_hold_effect(
    const char *verb, const char *const *targets, size_t ntargets,
    const char *effect_receipt, uid_t principal_uid, int plan_schema,
    const char *expected_cid, int lock_timeout_s, pkgx_transport *tx,
    char out_cid[PKGX_CID_LEN + 1], int *effect_issued, const char **detail) {
    *detail = "";
    *effect_issued = 0; /* nothing issued until the dpkg child is spawned */
    const char *err = nullptr;
    if (!pkgx_apt_init(&err)) {
        *detail = err;
        return PKGX_APT_INTERNAL;
    }
    pkgx_apt_set_lock_timeout(lock_timeout_s);

    const bool hold = (std::strcmp(verb, "apt.hold") == 0);
    const char *to_state = hold ? "hold" : "install";

    /* Frontend lock first (contention is retryable); then read the cache without
     * re-locking, so a failure there is a cache fault, not a lock timeout. */
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
    if (c == nullptr) {
        *detail = "cache";
        return PKGX_APT_INTERNAL;
    }

    /* Read the current selection for each target; keep only the ones that
     * actually change (an already-held hold, or an already-unheld unhold, is a
     * no-op that must not spend the receipt). Unknown target → resolve failure. */
    std::deque<HoldHolder> changes;
    for (size_t i = 0; i < ntargets; i++) {
        pkgCache::PkgIterator P = c->FindPkg(targets[i]);
        if (P.end()) {
            *detail = targets[i];
            return PKGX_APT_RESOLVE_FAILED;
        }
        const char *from_state = selection_word(P->SelectedState);
        /* hold/unhold toggles between install and hold; a target selected for
         * deinstall/purge (or unknown) is not a valid hold subject. Refuse it
         * explicitly rather than letting it reach a digest whose state grammar is
         * {hold, install} and fail there. */
        if (std::strcmp(from_state, "install") != 0 &&
            std::strcmp(from_state, "hold") != 0) {
            *detail = targets[i];
            return PKGX_APT_RESOLVE_FAILED;
        }
        if (std::strcmp(from_state, to_state) == 0) {
            continue; /* no change for this target */
        }
        HoldHolder h;
        h.package = targets[i];
        h.from = from_state;
        h.to = to_state;
        h.want_hold = hold;
        changes.push_back(std::move(h));
    }

    /* Build the borrowed hold records + the set-selections payload from the same
     * settled changes. Empty changes → the plan step returns NO_OP (unspent). */
    std::vector<pkgx_hold_record> holds;
    std::string payload;
    for (auto &h : changes) {
        pkgx_hold_record r;
        r.package = h.package.c_str();
        r.from_state = h.from.c_str();
        r.to_state = h.to.c_str();
        holds.push_back(r);
        payload += h.package;
        payload += ' ';
        payload += h.to; /* "hold" or "install": valid dpkg selection words */
        payload += '\n';
    }

    pkgx_plan_result pr = pkgx_plan_and_redeem_hold(
        verb, holds.data(), holds.size(), targets, ntargets, effect_receipt,
        principal_uid, plan_schema, expected_cid, pkgx_transport_tx, tx, out_cid,
        detail);

    switch (pr) {
    case PKGX_PLAN_NO_OP:
        return PKGX_APT_NO_OP;
    case PKGX_PLAN_NOT_OWNED:
        return PKGX_APT_NOT_OWNED;
    case PKGX_PLAN_HELD:
        return PKGX_APT_HELD; /* unreachable: hold has no held-package policy */
    case PKGX_PLAN_PROTECTED:
        return PKGX_APT_PROTECTED; /* unreachable: no protection policy */
    case PKGX_PLAN_NO_INTENT:
        return PKGX_APT_NO_INTENT;
    case PKGX_PLAN_INTERNAL:
        return PKGX_APT_INTERNAL;
    case PKGX_PLAN_OK:
        break;
    }

    HoldCommitCtx cc;
    cc.payload = &payload;
    cc.dpkg = _config->Find("Dir::Bin::dpkg", "/usr/bin/dpkg");
    cc.entered = false;
    cc.issued = false;
    cc.applied = false;
    pkgx_effect_gate(pr, out_cid, hold_commit, &cc);

    *effect_issued = cc.issued ? 1 : 0;
    int matched = cc.entered ? (selections_match(changes) ? 1 : 0) : 0;
    pkgx_apt_status st =
        pkgx_hold_classify(cc.entered, cc.applied ? 1 : 0, matched);
    switch (st) {
    case PKGX_APT_OK:
        *detail = "ok";
        break;
    case PKGX_APT_COMMIT_FAILED:
        *detail = cc.applied ? "selection_mismatch" : "set_selections";
        break;
    default:
        *detail = "internal";
        break;
    }
    return st;
}
