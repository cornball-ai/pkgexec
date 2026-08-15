/* Shared libapt scaffolding. See apt_common.hh. VM-runtime; CI links it only. */
#include "apt_common.hh"

#include <apt-pkg/configuration.h>
#include <apt-pkg/depcache.h>
#include <apt-pkg/error.h>
#include <apt-pkg/indexfile.h>
#include <apt-pkg/init.h>
#include <apt-pkg/metaindex.h>
#include <apt-pkg/pkgcache.h>
#include <apt-pkg/pkgsystem.h>

#include <cstring>
#include <set>

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

/* The dpkg selection word for a hold target's current selection (the tokens
 * `dpkg --set-selections` reads and writes). */
static const char *selection_word(unsigned char sel) {
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

/* The pending-configuration states `dpkg --configure --pending` acts on. HalfInstalled
 * is handled by the caller (unrepairable by configure), so it is not listed here. */
static const char *pending_state(unsigned char cur) {
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
        return nullptr;
    }
}

void pkgx_apt_map_sources(pkgSourceList &list, std::deque<PkgxSrcHolder> &holders,
                          std::vector<pkgx_src_record> &recs) {
    for (pkgSourceList::const_iterator I = list.begin(); I != list.end(); ++I) {
        metaIndex *mi = *I;
        if (mi == nullptr) {
            continue;
        }
        PkgxSrcHolder h;
        h.uri = mi->GetURI();
        h.suite = mi->GetDist();
        std::set<std::string> comps, arches;
        for (const IndexTarget &t : mi->GetIndexTargets()) {
            std::string comp = t.Option(IndexTarget::COMPONENT);
            if (!comp.empty()) {
                comps.insert(comp);
            }
            std::string arch = t.Option(IndexTarget::ARCHITECTURE);
            if (!arch.empty()) {
                arches.insert(arch);
            }
        }
        for (const std::string &c : comps) {
            h.components.push_back(c);
        }
        std::string signed_by = mi->GetSignedBy();
        if (!signed_by.empty()) {
            /* An inline armored key carries '=' and newlines that the schema-1
             * field grammar forbids; normalize it to a stable content-hash token so
             * the source's signing-key identity is still bound. Paths/fingerprints
             * (field-safe) pass through byte-for-byte. On a hash failure the
             * original is kept, so the digest fails closed rather than emitting a
             * wrong hash. See pkgx_signed_by_inline_token (digest.h). */
            char token[PKGX_SIGNEDBY_TOKEN_LEN + 1];
            if (pkgx_signed_by_inline_token(signed_by.c_str(), signed_by.size(),
                                            token) == 1) {
                signed_by = token;
            }
            h.okeys.push_back("signed-by");
            h.ovals.push_back(signed_by);
        }
        if (!arches.empty()) {
            std::string joined;
            for (const std::string &a : arches) {
                if (!joined.empty()) {
                    joined += ' ';
                }
                joined += a;
            }
            h.okeys.push_back("architectures");
            h.ovals.push_back(joined);
        }
        switch (mi->GetTrusted()) {
        case metaIndex::TRI_YES:
            h.okeys.push_back("trusted");
            h.ovals.push_back("yes");
            break;
        case metaIndex::TRI_NO:
            h.okeys.push_back("trusted");
            h.ovals.push_back("no");
            break;
        default:
            break; /* TRI_UNSET / TRI_DONTCARE: not explicitly set — omit */
        }
        holders.push_back(std::move(h));
    }
    for (auto &h : holders) {
        for (auto &c : h.components) {
            h.compp.push_back(c.c_str());
        }
        for (auto &k : h.okeys) {
            h.okeyp.push_back(k.c_str());
        }
        for (auto &v : h.ovals) {
            h.ovalp.push_back(v.c_str());
        }
        pkgx_src_record r;
        r.uri = h.uri.c_str();
        r.suite = h.suite.c_str();
        r.components = h.compp.empty() ? nullptr : h.compp.data();
        r.ncomponents = h.compp.size();
        r.opt_keys = h.okeyp.empty() ? nullptr : h.okeyp.data();
        r.opt_vals = h.ovalp.empty() ? nullptr : h.ovalp.data();
        r.nopts = h.okeyp.size();
        recs.push_back(r);
    }
}

pkgx_hold_map pkgx_apt_map_hold(pkgCache *cache, const char *const *targets,
                                size_t ntargets, bool hold,
                                std::deque<PkgxHoldHolder> &changes,
                                std::vector<pkgx_hold_record> &recs,
                                const char **offender) {
    const char *to_state = hold ? "hold" : "install";
    for (size_t i = 0; i < ntargets; i++) {
        pkgCache::PkgIterator P = cache->FindPkg(targets[i]);
        if (P.end()) {
            if (offender != nullptr) {
                *offender = targets[i];
            }
            return PKGX_HOLD_MAP_UNKNOWN;
        }
        const char *from_state = selection_word(P->SelectedState);
        /* hold/unhold toggles between install and hold; a target selected for
         * deinstall/purge (or unknown) is not a valid hold subject. */
        if (std::strcmp(from_state, "install") != 0 &&
            std::strcmp(from_state, "hold") != 0) {
            if (offender != nullptr) {
                *offender = targets[i];
            }
            return PKGX_HOLD_MAP_INVALID;
        }
        if (std::strcmp(from_state, to_state) == 0) {
            continue; /* no change for this target */
        }
        PkgxHoldHolder h;
        h.package = targets[i];
        h.from = from_state;
        h.to = to_state;
        h.want_hold = hold;
        changes.push_back(std::move(h));
    }
    for (auto &h : changes) {
        pkgx_hold_record r;
        r.package = h.package.c_str();
        r.from_state = h.from.c_str();
        r.to_state = h.to.c_str();
        recs.push_back(r);
    }
    return PKGX_HOLD_MAP_OK;
}

pkgx_cfg_map pkgx_apt_map_configure(pkgCache *cache,
                                    std::deque<PkgxCfgHolder> &holders,
                                    std::vector<pkgx_cfg_record> &recs,
                                    const char **name) {
    for (pkgCache::PkgIterator P = cache->PkgBegin(); !P.end(); ++P) {
        if (P->CurrentState == pkgCache::State::HalfInstalled) {
            if (name != nullptr) {
                *name = P.Name();
            }
            return PKGX_CFG_MAP_HALF_INSTALLED;
        }
        const char *state = pending_state(P->CurrentState);
        if (state == nullptr) {
            continue;
        }
        PkgxCfgHolder h;
        h.package = P.Name();
        h.arch = P.Arch();
        pkgCache::VerIterator cur = P.CurrentVer();
        h.version = cur.end() ? "" : cur.VerStr();
        h.state = state;
        holders.push_back(std::move(h));
    }
    for (auto &h : holders) {
        pkgx_cfg_record r;
        r.package = h.package.c_str();
        r.architecture = h.arch.c_str();
        r.current_version = h.version.c_str();
        r.state = h.state.c_str();
        recs.push_back(r);
    }
    return PKGX_CFG_MAP_OK;
}

bool pkgx_apt_ground_truth_broken() {
    /* Isolate the fresh read from whatever the transaction left on the global
     * error stack, so neither the open nor the scan inherits stale messages. */
    _error->PushToStack();
    bool bad = true; /* fail-safe: if we cannot verify, treat it as broken */
    pkgCacheFile fresh;
    if (fresh.Open(nullptr, false)) {
        pkgCache *pc = fresh.GetPkgCache();
        pkgDepCache *fdc = fresh.GetDepCache();
        if (pc != nullptr && fdc != nullptr) {
            /* BrokenCount only sees unsatisfied dependencies. A failed maintainer
             * script can leave a package unpacked / half-configured / half-
             * installed / triggers-pending-or-awaited, or reinstall-required, with
             * its dependencies satisfied — PkgIterator::State() != NeedsNothing
             * catches every such incomplete package. */
            bad = (fdc->BrokenCount() != 0);
            for (pkgCache::PkgIterator P = pc->PkgBegin(); !bad && !P.end(); ++P) {
                if (P.State() != pkgCache::PkgIterator::NeedsNothing) {
                    bad = true;
                }
            }
        }
    }
    _error->RevertToStack(); /* drop the fresh read's errors; restore the prior */
    return bad;
}
