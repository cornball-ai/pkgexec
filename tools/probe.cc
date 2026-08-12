/* Read-only libapt-pkg API test (apt-mutation plan, build-order step 0). It
 * proves, before any privileged code is written, that:
 *
 *   1. the read-only cache/policy/depcache surface works and the plan-digest
 *      fields (versions, essential/held/auto/protected flags) are reachable;
 *   2. the transaction-marker mechanism works — apt records `Commandline:` in
 *      /var/log/apt/history.log from `CommandLine::AsString`, so stamping the
 *      Runix correlation_id there is how the native dpkg transaction is later
 *      reconciled to the Runix operation;
 *   3. the exact lock / resolve / commit symbols the helper will call
 *      (`_system->Lock`, `pkgCacheFile::Open(..., WithLock=true)`,
 *      `pkgProblemResolver`, `pkgApplyStatus`/`pkgAllUpgrade`/`pkgDistUpgrade`,
 *      `pkgSystem::CreatePM` -> `pkgPackageManager::GetArchives`/`DoInstall`,
 *      `pkgAcquire`) TYPE-CHECK and LINK — via a function that is compiled and
 *      linked but never executed (guarded by a `volatile` false), so nothing is
 *      locked, resolved, or committed here.
 *
 * A diagnostic, never a production entrypoint: not built by `make all`/`make
 * check`, not installed, performs no mutation.
 *
 *   make probe            # requires libapt-pkg-dev
 *   ./pkgexec-probe [pkg]  # default: bash
 */
#include <apt-pkg/acquire.h>
#include <apt-pkg/algorithms.h>
#include <apt-pkg/cachefile.h>
#include <apt-pkg/configuration.h>
#include <apt-pkg/depcache.h>
#include <apt-pkg/init.h>
#include <apt-pkg/packagemanager.h>
#include <apt-pkg/pkgcache.h>
#include <apt-pkg/pkgsystem.h>
#include <apt-pkg/policy.h>
#include <apt-pkg/upgrade.h>

#include <iostream>

/* Never executed at runtime (see the `volatile` guard in main). Exists only to
 * type-check and link the exact commit-path symbols the helper will use, so the
 * spike proves they resolve. It locks/resolves/commits NOTHING because it never
 * runs. */
static void commit_path_link_check(pkgCacheFile &cache) {
    cache.Open(nullptr, true); /* WithLock=true: the locking open */
    pkgDepCache *dc = cache.GetDepCache();
    _system->Lock(); /* dpkg frontend lock */
    pkgProblemResolver resolver(dc);
    resolver.Resolve();
    pkgApplyStatus(*dc);
    APT::Upgrade::Upgrade(*dc, APT::Upgrade::ALLOW_EVERYTHING);
    pkgMinimizeUpgrade(*dc);
    pkgAcquire fetcher;
    pkgPackageManager *pm = _system->CreatePM(dc);
    pm->GetArchives(&fetcher, nullptr, nullptr);
    pm->DoInstall(nullptr);
    delete pm;
}

int main(int argc, char **argv) {
    if (!pkgInitConfig(*_config)) {
        std::cerr << "pkgInitConfig failed\n";
        return 1;
    }
    if (!pkgInitSystem(*_config, _system)) {
        std::cerr << "pkgInitSystem failed\n";
        return 1;
    }

    pkgCacheFile cache;
    if (!cache.Open(nullptr, false)) { /* WithLock=false: read-only */
        std::cerr << "cache open (read-only) failed\n";
        return 1;
    }
    pkgCache *c = cache.GetPkgCache();
    pkgDepCache *dc = cache.GetDepCache();
    pkgPolicy *pol = cache.GetPolicy();
    if (c == nullptr || dc == nullptr || pol == nullptr) {
        std::cerr << "cache/depcache/policy unavailable\n";
        return 1;
    }

    const char *target = (argc > 1) ? argv[1] : "bash";
    pkgCache::PkgIterator P = c->FindPkg(target);
    if (P.end()) {
        std::cout << "not found: " << target << "\n";
        return 0;
    }

    pkgCache::VerIterator cur = P.CurrentVer();
    pkgCache::VerIterator cand = pol->GetCandidateVer(P);

    std::cout << "package=" << P.Name() << "\n";
    std::cout << "architecture=" << P.Arch() << "\n";
    std::cout << "current_version=" << (cur.end() ? "" : cur.VerStr()) << "\n";
    std::cout << "candidate_version=" << (cand.end() ? "" : cand.VerStr()) << "\n";
    std::cout << "essential="
              << (((P->Flags & pkgCache::Flag::Essential) != 0) ? "yes" : "no")
              << "\n";
    std::cout << "important="
              << (((P->Flags & pkgCache::Flag::Important) != 0) ? "yes" : "no")
              << "\n";
    std::cout << "held="
              << ((P->SelectedState == pkgCache::State::Hold) ? "yes" : "no")
              << "\n";
    std::cout << "auto_installed="
              << ((((*dc)[P].Flags & pkgCache::Flag::Auto) != 0) ? "yes" : "no")
              << "\n";
    std::cout << "system_locked=" << (_system->IsLocked() ? "yes" : "no") << "\n";

    /* Transaction-marker round-trip: this is the key apt writes to history.log's
     * Commandline: field, which the helper stamps with the correlation_id. */
    _config->Set("CommandLine::AsString", "runix:00000000000000000000-0000000000000000");
    std::cout << "marker=" << _config->Find("CommandLine::AsString") << "\n";

    volatile int never = 0; /* keeps the branch (and its symbol refs) at any -O */
    if (never) {
        commit_path_link_check(cache);
    }
    return 0;
}
