/* Read-only libapt-pkg API spike (apt-mutation plan, build-order step 0). It
 * confirms, before any privileged code is written, that the exact
 * lock/resolve/commit surface the helper will use links and the plan-digest
 * fields are reachable — WITHOUT taking a lock, resolving, or committing
 * anything. It is a diagnostic, never a production entrypoint: it is not built
 * by `make all`/`make check`, is not installed, and performs no mutation.
 *
 *   make probe            # requires libapt-pkg-dev
 *   ./pkgexec-probe [pkg]  # default: bash
 */
#include <apt-pkg/cachefile.h>
#include <apt-pkg/depcache.h>
#include <apt-pkg/init.h>
#include <apt-pkg/pkgcache.h>
#include <apt-pkg/pkgsystem.h>
#include <apt-pkg/policy.h>

/* Included only to confirm the commit-path headers parse and link; nothing here
 * is invoked (read-only spike). */
#include <apt-pkg/acquire.h>
#include <apt-pkg/algorithms.h>
#include <apt-pkg/packagemanager.h>

#include <iostream>

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
    return 0;
}
