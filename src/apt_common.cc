/* Shared libapt scaffolding. See apt_common.hh. VM-runtime; CI links it only. */
#include "apt_common.hh"

#include <apt-pkg/configuration.h>
#include <apt-pkg/depcache.h>
#include <apt-pkg/init.h>
#include <apt-pkg/pkgcache.h>
#include <apt-pkg/pkgsystem.h>

bool pkgx_apt_init(const char **err) {
    if (!pkgInitConfig(*_config)) {
        if (err != nullptr) {
            *err = "apt config init failed";
        }
        return false;
    }
    if (!pkgInitSystem(*_config, _system)) {
        if (err != nullptr) {
            *err = "apt system init failed";
        }
        return false;
    }
    return true;
}

void pkgx_apt_set_lock_timeout(int seconds) {
    if (seconds < 0) {
        seconds = 0;
    }
    _config->Set("DPkg::Lock::Timeout", seconds);
}

void pkgx_apt_map_txn(pkgCache *cache, pkgDepCache *dc,
                      std::deque<PkgxHolder> &holders,
                      std::vector<pkgx_txn_record> &recs) {
    for (pkgCache::PkgIterator P = cache->PkgBegin(); !P.end(); ++P) {
        pkgDepCache::StateCache &st = (*dc)[P];
        PkgxHolder h;
        if (st.Delete()) {
            h.action = (st.iFlags & pkgDepCache::Purge) ? "purge" : "remove";
        } else if (st.NewInstall()) {
            h.action = "install";
        } else if (st.Upgrade()) {
            h.action = "upgrade";
        } else if (st.Downgrade()) {
            h.action = "downgrade";
        } else {
            continue; /* no change to this package */
        }
        h.package = P.Name();
        h.arch = P.Arch();
        pkgCache::VerIterator cur = P.CurrentVer();
        pkgCache::VerIterator iv = st.InstVerIter(*dc);
        h.from = cur.end() ? "" : cur.VerStr();
        h.to = iv.end() ? "" : iv.VerStr();
        /* Flags the digest binds. `essential` (Flag::Essential) and `protected`
         * (Priority: required, or Flag::Important) are distinct; hold/auto are
         * read directly. StateCache::Protect() is deliberately NOT consulted —
         * the resolver sets it on requested targets, a different notion. */
        if (P->SelectedState == pkgCache::State::Hold) {
            h.flags.push_back("hold");
        }
        if ((st.Flags & pkgCache::Flag::Auto) != 0) {
            h.flags.push_back("auto");
        }
        if ((P->Flags & pkgCache::Flag::Essential) != 0) {
            h.flags.push_back("essential");
        }
        pkgCache::VerIterator pver = !cur.end() ? cur : iv;
        bool required = !pver.end() && pver->Priority == pkgCache::State::Required;
        if (required || (P->Flags & pkgCache::Flag::Important) != 0) {
            h.flags.push_back("protected");
        }
        for (auto &f : h.flags) {
            h.flagp.push_back(f.c_str());
        }
        holders.push_back(std::move(h));
    }
    /* Build the borrowed C records from the settled deque elements (stable
     * addresses), so the pointers stay valid for the digest call. */
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
}
