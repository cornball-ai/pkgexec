/* Locked libapt resolve diagnostic (apt-mutation, all nine verbs). Under the held
 * dpkg lock it maps the current state to the digest's record model, runs the
 * trusted-side policy/ownership check, and prints the canonical resource and the
 * schema-1 plan_hash for the verb. It STOPS THERE: it never redeems (no transport
 * is wired here) and never commits (no GetArchives/DoInstall, no dpkg spawn). It
 * is the linkage proof for the locked context, and — on a disposable VM only — the
 * issue-time digest source the acceptance driver (rab-exercise) binds into a
 * receipt. Its runtime, which takes the real dpkg lock, runs on the VM only.
 *
 * It is an ORACLE, not a policy authority: successful receipt redemption is what
 * proves this preview matched the effector's atomic resolve. To keep it honest it
 * builds every descriptor through the SAME shared apt_common builders the effectors
 * use (pkgx_apt_map_txn / _sources / _hold / _configure) plus the shared
 * pkgx_digest_* and policy functions — no mirrored enumeration, so a matching cache
 * yields a matching hash by construction. The digest sorts records bytewise, so only
 * the record SET must match, not the order.
 *
 * Contracts it enforces so it never hands the driver a plan the effector would
 * refuse or no-op:
 *   - verbs are a strict allowlist with production arity (no implicit target, no
 *     unknown-verb fallthrough);
 *   - upgrade/dist_upgrade are real whole-system plans (APT::Upgrade::Upgrade),
 *     never target installs;
 *   - a policy/ownership violation, or a resource/digest failure, exits NONZERO
 *     and emits NO plan_hash;
 *   - an empty resolved set is reported `status=noop` (exit 3) so the driver never
 *     opens an intent and spends a needless receipt.
 *
 *   make plan                                  # compile + link (the CI gate)
 *   sudo ./pkgexec-plan apt.install nginx      # VM-only: needs root for the lock
 *   sudo ./pkgexec-plan apt.upgrade            # whole-system; rejects targets
 *   sudo ./pkgexec-plan apt.update             # whole source list
 *   sudo ./pkgexec-plan apt.hold nginx         # selection -> hold
 *   sudo ./pkgexec-plan apt.configure          # pending-config set
 *
 * Output is machine-readable `key=value` lines; the driver reads `resource=` and
 * `plan_hash=` (present only on exit 0).
 */
#include "../src/apt_common.hh" /* the shared apt_common descriptor builders */
#include "../src/digest.h"
#include "../src/policy.h"

#include <apt-pkg/algorithms.h>
#include <apt-pkg/cachefile.h>
#include <apt-pkg/configuration.h>
#include <apt-pkg/depcache.h>
#include <apt-pkg/init.h>
#include <apt-pkg/pkgcache.h>
#include <apt-pkg/pkgsystem.h>
#include <apt-pkg/sourcelist.h>
#include <apt-pkg/upgrade.h>

#include <deque>
#include <iostream>
#include <string>
#include <vector>

namespace {

/* Distinct exit codes the acceptance driver dispatches on. */
enum {
    PLAN_OK = 0,       /* a usable plan: resource= and plan_hash= printed */
    PLAN_INTERNAL = 1, /* cache/resolve/resource/digest failure: no plan */
    PLAN_USAGE = 2,    /* unknown verb or wrong arity */
    PLAN_NOOP = 3,     /* empty resolved set: no effect, do not issue a receipt */
    PLAN_REFUSED = 4   /* policy/ownership/broken refusal: no plan, receipt unspent */
};

/* Compute the canonical resource for a target list; -1 on failure. */
int resource_for(const char *const *targets, size_t n, std::string &out) {
    char *r = nullptr;
    if (pkgx_resource(targets, n, &r) != 0 || r == nullptr) {
        return -1;
    }
    out = r;
    free(r);
    return 0;
}

void emit_plan(const std::string &resource, const char *hex) {
    std::cout << "resource=" << resource << "\n";
    std::cout << "plan_hash=" << hex << "\n";
    std::cout << "note=would redeem+commit under the activation slice (not here)\n";
}

/* -------- A. transactions (install/remove/purge/upgrade/dist_upgrade). Reuses
 * the effector's resolve shape (APT::Upgrade for the whole-system verbs) and the
 * shared pkgx_apt_map_txn record mapping. -------- */
int plan_txn(pkgCacheFile &cache, const std::string &verb,
             const std::vector<std::string> &targets) {
    const bool removal = (verb == "apt.remove" || verb == "apt.purge");
    const bool purge = (verb == "apt.purge");
    const bool upgrade = (verb == "apt.upgrade");
    const bool dist = (verb == "apt.dist_upgrade");
    pkgCache *c = cache.GetPkgCache();
    pkgDepCache *dc = cache.GetDepCache();
    if (c == nullptr || dc == nullptr) {
        std::cerr << "cache unavailable\n";
        return PLAN_INTERNAL;
    }
    if (upgrade || dist) {
        const int mode = dist ? APT::Upgrade::ALLOW_EVERYTHING
                              : APT::Upgrade::FORBID_REMOVE_PACKAGES;
        if (!APT::Upgrade::Upgrade(*dc, mode)) {
            std::cerr << "resolve failed\n";
            return PLAN_INTERNAL;
        }
    } else {
        pkgProblemResolver resolver(dc);
        for (const auto &t : targets) {
            pkgCache::PkgIterator P = c->FindPkg(t);
            if (P.end()) {
                std::cerr << "unknown package: " << t << "\n";
                return PLAN_INTERNAL;
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
            std::cerr << "resolve failed\n";
            return PLAN_INTERNAL;
        }
    }
    std::deque<PkgxHolder> holders;
    std::vector<pkgx_txn_record> recs;
    pkgx_apt_map_txn(c, dc, holders, recs);
    std::cout << "verb=" << verb << " resolved_records=" << recs.size() << "\n";
    if (recs.empty()) {
        std::cout << "status=noop\n";
        return PLAN_NOOP;
    }
    const char *offender = nullptr;
    switch (pkgx_policy_check(recs.data(), recs.size(), &offender)) {
    case PKGX_POLICY_OK:
        break;
    case PKGX_POLICY_NOT_OWNED:
        std::cout << "status=refused reason=not_owned offender="
                  << (offender ? offender : "") << "\n";
        return PLAN_REFUSED;
    case PKGX_POLICY_HELD:
        std::cout << "status=refused reason=held offender="
                  << (offender ? offender : "") << "\n";
        return PLAN_REFUSED;
    case PKGX_POLICY_PROTECTED:
        std::cout << "status=refused reason=protected offender="
                  << (offender ? offender : "") << "\n";
        return PLAN_REFUSED;
    }
    std::vector<const char *> tp;
    for (const auto &t : targets) {
        tp.push_back(t.c_str());
    }
    std::string resource;
    if (resource_for(tp.data(), tp.size(), resource) != 0) {
        std::cerr << "resource construction failed\n";
        return PLAN_INTERNAL;
    }
    char hex[PKGEXEC_DIGEST_HEX + 1];
    if (pkgx_digest_pkg_txn(verb.c_str(), recs.data(), recs.size(), hex, nullptr,
                            nullptr) != 0) {
        std::cerr << "digest failed\n";
        return PLAN_INTERNAL;
    }
    emit_plan(resource, hex);
    return PLAN_OK;
}

/* -------- B. update (apt.update): the shared pkgx_apt_map_sources enumeration. No
 * package policy. -------- */
int plan_update() {
    pkgSourceList list;
    if (!list.ReadMainList()) {
        std::cerr << "sources unreadable\n";
        return PLAN_INTERNAL;
    }
    std::deque<PkgxSrcHolder> holders;
    std::vector<pkgx_src_record> recs;
    pkgx_apt_map_sources(list, holders, recs);
    std::cout << "verb=apt.update resolved_records=" << recs.size() << "\n";
    if (recs.empty()) {
        std::cout << "status=noop\n"; /* no configured sources: nothing to refresh */
        return PLAN_NOOP;
    }
    char hex[PKGEXEC_DIGEST_HEX + 1];
    if (pkgx_digest_update(recs.data(), recs.size(), hex, nullptr, nullptr) != 0) {
        std::cerr << "digest failed\n";
        return PLAN_INTERNAL;
    }
    emit_plan("", hex); /* whole source list: the empty resource token */
    return PLAN_OK;
}

/* -------- C. hold / unhold: the shared pkgx_apt_map_hold selection read + change
 * filter, then the same ownership refusal (never touch a rapt-owned package). ---- */
int plan_hold(pkgCacheFile &cache, const std::string &verb,
              const std::vector<std::string> &targets) {
    pkgCache *c = cache.GetPkgCache();
    if (c == nullptr) {
        std::cerr << "cache unavailable\n";
        return PLAN_INTERNAL;
    }
    bool hold = (verb == "apt.hold");
    std::vector<const char *> tp;
    for (const auto &t : targets) {
        tp.push_back(t.c_str());
    }
    std::deque<PkgxHoldHolder> changes;
    std::vector<pkgx_hold_record> holds;
    const char *offender = nullptr;
    pkgx_hold_map hm =
        pkgx_apt_map_hold(c, tp.data(), tp.size(), hold, changes, holds, &offender);
    if (hm == PKGX_HOLD_MAP_UNKNOWN) {
        std::cerr << "unknown package: " << (offender ? offender : "") << "\n";
        return PLAN_INTERNAL;
    }
    if (hm == PKGX_HOLD_MAP_INVALID) {
        std::cerr << "not a hold subject: " << (offender ? offender : "") << "\n";
        return PLAN_INTERNAL;
    }
    std::cout << "verb=" << verb << " resolved_records=" << changes.size() << "\n";
    if (changes.empty()) {
        std::cout << "status=noop\n"; /* every target already in the target state */
        return PLAN_NOOP;
    }
    /* Ownership is the only policy for a selection change (apt_hold plan step). */
    for (const auto &h : changes) {
        if (pkgx_is_rapt_owned(h.package.c_str())) {
            std::cout << "status=refused reason=not_owned offender=" << h.package
                      << "\n";
            return PLAN_REFUSED;
        }
    }
    std::string resource;
    if (resource_for(tp.data(), tp.size(), resource) != 0) { /* over ALL targets */
        std::cerr << "resource construction failed\n";
        return PLAN_INTERNAL;
    }
    char hex[PKGEXEC_DIGEST_HEX + 1];
    if (pkgx_digest_hold(verb.c_str(), holds.data(), holds.size(), hex, nullptr,
                         nullptr) != 0) {
        std::cerr << "digest failed\n";
        return PLAN_INTERNAL;
    }
    emit_plan(resource, hex);
    return PLAN_OK;
}

/* -------- D. configure: the shared pkgx_apt_map_configure enumeration (with its
 * half-installed pre-plan BROKEN refusal) and the same ownership refusal. -------- */
int plan_configure(pkgCacheFile &cache) {
    pkgCache *c = cache.GetPkgCache();
    if (c == nullptr) {
        std::cerr << "cache unavailable\n";
        return PLAN_INTERNAL;
    }
    std::deque<PkgxCfgHolder> holders;
    std::vector<pkgx_cfg_record> cfgs;
    const char *half_installed = nullptr;
    if (pkgx_apt_map_configure(c, holders, cfgs, &half_installed) ==
        PKGX_CFG_MAP_HALF_INSTALLED) {
        /* Unrepairable by configure: the effector refuses BROKEN before the receipt
         * is spent, so there is no plan to bind. */
        std::cout << "verb=apt.configure status=refused reason=broken offender="
                  << (half_installed ? half_installed : "") << "\n";
        return PLAN_REFUSED;
    }
    std::cout << "verb=apt.configure resolved_records=" << cfgs.size() << "\n";
    if (cfgs.empty()) {
        std::cout << "status=noop\n"; /* nothing pending: nothing to configure */
        return PLAN_NOOP;
    }
    /* Ownership: configuring an r-* package runs its maintainer scripts. */
    for (const auto &h : holders) {
        if (pkgx_is_rapt_owned(h.package.c_str())) {
            std::cout << "status=refused reason=not_owned offender=" << h.package
                      << "\n";
            return PLAN_REFUSED;
        }
    }
    char hex[PKGEXEC_DIGEST_HEX + 1];
    if (pkgx_digest_configure(cfgs.data(), cfgs.size(), hex, nullptr, nullptr) !=
        0) {
        std::cerr << "digest failed\n";
        return PLAN_INTERNAL;
    }
    emit_plan("pending", hex); /* the fixed configure resource token */
    return PLAN_OK;
}

/* Strict verb allowlist with production arity. Returns 0 if (verb, ntargets) is a
 * legal combination, or prints usage and returns PLAN_USAGE. */
int check_verb_arity(const std::string &verb, size_t ntargets) {
    struct Spec {
        const char *verb;
        bool needs_targets; /* true: >=1 target required; false: exactly 0 */
    };
    static const Spec specs[] = {
        {"apt.install", true},  {"apt.remove", true},
        {"apt.purge", true},    {"apt.upgrade", false},
        {"apt.dist_upgrade", false}, {"apt.update", false},
        {"apt.hold", true},     {"apt.unhold", true},
        {"apt.configure", false}};
    for (const Spec &s : specs) {
        if (verb == s.verb) {
            if (s.needs_targets && ntargets == 0) {
                std::cerr << "usage: " << verb << " needs >=1 package\n";
                return PLAN_USAGE;
            }
            if (!s.needs_targets && ntargets != 0) {
                std::cerr << verb << " is whole-system; it takes no packages\n";
                return PLAN_USAGE;
            }
            return 0;
        }
    }
    std::cerr << "unknown verb: " << verb << "\n";
    return PLAN_USAGE;
}

} /* namespace */

int main(int argc, char **argv) {
    if (argc < 2) {
        std::cerr << "usage: pkgexec-plan <apt.verb> [pkg ...]\n";
        return PLAN_USAGE;
    }
    std::string verb = argv[1];
    std::vector<std::string> targets;
    for (int i = 2; i < argc; i++) {
        targets.push_back(argv[i]);
    }
    int arity = check_verb_arity(verb, targets.size());
    if (arity != 0) {
        return arity;
    }

    if (!pkgInitConfig(*_config) || !pkgInitSystem(*_config, _system)) {
        std::cerr << "apt init failed\n";
        return PLAN_INTERNAL;
    }

    /* update reads the source list directly and needs no package cache. */
    if (verb == "apt.update") {
        return plan_update();
    }

    /* Every other verb reads the locked package cache (needs root on a VM). */
    pkgCacheFile cache;
    if (!cache.Open(nullptr, true)) { /* WithLock=true: the dpkg frontend lock */
        std::cerr << "locked cache open failed (needs root on a disposable VM)\n";
        return PLAN_INTERNAL;
    }
    if (verb == "apt.hold" || verb == "apt.unhold") {
        return plan_hold(cache, verb, targets);
    }
    if (verb == "apt.configure") {
        return plan_configure(cache);
    }
    return plan_txn(cache, verb, targets);
}
