/* Shared libapt scaffolding. See apt_common.hh. VM-runtime; CI links it only. */
#include "apt_common.hh"

#include <apt-pkg/configuration.h>
#include <apt-pkg/depcache.h>
#include <apt-pkg/init.h>
#include <apt-pkg/pkgcache.h>
#include <apt-pkg/pkgsystem.h>

#include <errno.h>
#include <spawn.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

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

int pkgx_spawn_wait(const char *const argv[], const char *input) {
    int in[2] = {-1, -1};
    if (input != nullptr && pipe(in) != 0) {
        return -1;
    }
    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    if (input != nullptr) {
        posix_spawn_file_actions_adddup2(&fa, in[0], STDIN_FILENO);
        posix_spawn_file_actions_addclose(&fa, in[0]);
        posix_spawn_file_actions_addclose(&fa, in[1]);
    }
    pid_t pid = 0;
    int rc = posix_spawn(&pid, argv[0], &fa, nullptr,
                         const_cast<char *const *>(argv), environ);
    posix_spawn_file_actions_destroy(&fa);
    if (input != nullptr) {
        close(in[0]);
        if (rc != 0) {
            close(in[1]);
            return -1;
        }
        size_t len = strlen(input);
        size_t off = 0;
        while (off < len) {
            ssize_t w = write(in[1], input + off, len - off);
            if (w < 0) {
                if (errno == EINTR) {
                    continue;
                }
                break; /* child may have exited; the wait below reports it */
            }
            off += (size_t) w;
        }
        close(in[1]);
    } else if (rc != 0) {
        return -1;
    }
    int status = 0;
    if (waitpid(pid, &status, 0) != pid) {
        return -1;
    }
    return (WIFEXITED(status) && WEXITSTATUS(status) == 0) ? 0 : -1;
}
