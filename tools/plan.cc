/* Locked libapt resolve diagnostic (apt-mutation slice 2). Under the held dpkg
 * frontend lock it resolves a transaction, maps it to the digest's record model,
 * runs the trusted-side policy check, and prints the canonical resource and
 * schema-1 digest. It STOPS THERE: it never redeems (no transport is wired here)
 * and never commits (no GetArchives/DoInstall). It is the linkage proof for the
 * locked context — the C++ resolve path compiles and links libapt + the C helper
 * (digest/policy) — while its runtime behaviour, which takes the real dpkg lock,
 * is validated only on a disposable VM (never in CI, never on a real host).
 *
 *   make plan                       # compile + link (the CI gate)
 *   sudo ./pkgexec-plan apt.install nginx   # VM-only: needs root for the lock
 */
#include "../src/digest.h"
#include "../src/policy.h"

#include <apt-pkg/algorithms.h>
#include <apt-pkg/cachefile.h>
#include <apt-pkg/configuration.h>
#include <apt-pkg/depcache.h>
#include <apt-pkg/init.h>
#include <apt-pkg/pkgcache.h>
#include <apt-pkg/pkgsystem.h>

#include <deque>
#include <iostream>
#include <string>
#include <vector>

/* Per-record string storage with stable addresses (std::deque never moves its
 * elements), so the C record's borrowed pointers stay valid through the calls. */
struct Holder {
    std::string package, arch, action, from, to;
    std::vector<std::string> flags;
    std::vector<const char *> flagp;
};

int main(int argc, char **argv) {
    std::string verb = (argc > 1) ? argv[1] : "apt.install";
    std::vector<std::string> targets;
    for (int i = 2; i < argc; i++) {
        targets.push_back(argv[i]);
    }
    if (targets.empty()) {
        targets.push_back("nginx");
    }
    bool removal = (verb == "apt.remove" || verb == "apt.purge");
    bool purge = (verb == "apt.purge");

    if (!pkgInitConfig(*_config) || !pkgInitSystem(*_config, _system)) {
        std::cerr << "apt init failed\n";
        return 1;
    }

    pkgCacheFile cache;
    if (!cache.Open(nullptr, true)) { /* WithLock=true: the dpkg frontend lock */
        std::cerr << "locked cache open failed (needs root on a disposable VM)\n";
        return 1;
    }
    pkgCache *c = cache.GetPkgCache();
    pkgDepCache *dc = cache.GetDepCache();
    if (c == nullptr || dc == nullptr) {
        std::cerr << "cache unavailable\n";
        return 1;
    }

    pkgProblemResolver resolver(dc);
    for (const auto &t : targets) {
        pkgCache::PkgIterator P = c->FindPkg(t);
        if (P.end()) {
            std::cerr << "unknown package: " << t << "\n";
            return 1;
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
        return 1;
    }

    std::deque<Holder> holders;
    for (pkgCache::PkgIterator P = c->PkgBegin(); !P.end(); ++P) {
        pkgDepCache::StateCache &st = (*dc)[P];
        Holder h;
        if (st.Delete()) {
            h.action = (st.iFlags & pkgDepCache::Purge) ? "purge" : "remove";
        } else if (st.NewInstall()) {
            h.action = "install";
        } else if (st.Upgrade()) {
            h.action = "upgrade";
        } else if (st.Downgrade()) {
            h.action = "downgrade";
        } else {
            continue; /* no change */
        }
        h.package = P.Name();
        h.arch = P.Arch();
        pkgCache::VerIterator cur = P.CurrentVer();
        pkgCache::VerIterator iv = st.InstVerIter(*dc);
        h.from = cur.end() ? "" : cur.VerStr();
        h.to = iv.end() ? "" : iv.VerStr();
        /* Flags the digest binds. `protected`-set detection is completed at the
         * VM gate; essential/hold/auto are read here. */
        if (P->SelectedState == pkgCache::State::Hold) {
            h.flags.push_back("hold");
        }
        if ((st.Flags & pkgCache::Flag::Auto) != 0) {
            h.flags.push_back("auto");
        }
        if ((P->Flags & pkgCache::Flag::Essential) != 0) {
            h.flags.push_back("essential");
        }
        for (auto &f : h.flags) {
            h.flagp.push_back(f.c_str());
        }
        holders.push_back(std::move(h));
    }

    std::vector<pkgx_txn_record> recs;
    for (auto &h : holders) {
        pkgx_txn_record r;
        r.package = h.package.c_str();
        r.architecture = h.arch.c_str();
        r.action = h.action.c_str();
        r.from_version = h.from.c_str();
        r.to_version = h.to.c_str();
        r.flags = h.flagp.empty() ? nullptr : h.flagp.data();
        r.nflags = h.flagp.size();
        recs.push_back(r);
    }

    const char *offender = nullptr;
    pkgx_policy_result pol = pkgx_policy_check(recs.data(), recs.size(), &offender);
    std::cout << "verb=" << verb << " resolved_records=" << recs.size() << "\n";
    std::cout << "policy=" << (int) pol
              << (offender ? std::string(" offender=") + offender : "") << "\n";

    std::vector<const char *> tp;
    for (auto &t : targets) {
        tp.push_back(t.c_str());
    }
    char *resource = nullptr;
    if (pkgx_resource(tp.data(), tp.size(), &resource) == 0) {
        std::cout << "resource=" << resource << "\n";
        free(resource);
    }
    char hex[PKGEXEC_DIGEST_HEX + 1];
    if (pkgx_digest_pkg_txn(verb.c_str(), recs.data(), recs.size(), hex, nullptr,
                            nullptr) == 0) {
        std::cout << "plan_hash=" << hex << "\n";
    }
    std::cout << "note=would redeem+commit under the activation slice (not here)\n";
    return 0;
}
