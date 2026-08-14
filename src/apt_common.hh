/* Shared libapt scaffolding for the four commit lifecycles (activation slice):
 * one-time init, the bounded dpkg lock wait, a headless acquire status, the
 * resolved-transaction record mapping, and a no-shell dpkg spawn helper. The
 * per-mechanism effectors (apt_effect.hh) build on this; each links only what it
 * needs so a per-verb binary pulls in only its mechanism (entrypoint isolation).
 *
 * Everything here is VM-runtime: it opens the real dpkg lock and, for the
 * committers, mutates the host. CI compiles and links it as the mutation-path
 * linkage proof only; behaviour is validated on a disposable VM. */
#ifndef PKGEXEC_APT_COMMON_HH
#define PKGEXEC_APT_COMMON_HH

#include "digest.h" /* pkgx_txn_record */

#include <apt-pkg/acquire.h>
#include <apt-pkg/cachefile.h>
#include <apt-pkg/sourcelist.h>

#include <deque>
#include <string>
#include <vector>

/* Per-record string storage with stable addresses (std::deque never moves its
 * elements), so a C record's borrowed pointers stay valid through the calls. */
struct PkgxHolder {
    std::string package, arch, action, from, to;
    std::vector<std::string> flags;
    std::vector<const char *> flagp;
};

/* Initialize libapt config + system exactly once per process. false + *err on
 * failure. */
bool pkgx_apt_init(const char **err);

/* Bound the frontend-lock wait (DPkg::Lock::Timeout, seconds). 0 = fail fast. */
void pkgx_apt_set_lock_timeout(int seconds);

/* Map a resolved dep cache to the schema-1 record model over the WHOLE
 * transaction (target + every pulled dependency), matching the digest grammar.
 * `holders` provides stable storage; `recs` borrows from it. */
void pkgx_apt_map_txn(pkgCache *cache, pkgDepCache *dc,
                      std::deque<PkgxHolder> &holders,
                      std::vector<pkgx_txn_record> &recs);

/* Per-verb stable record storage for the update/hold/configure descriptors, shared so
 * the effector and the read-only planner build byte-identical records from ONE code
 * path (no mirrored enumeration). The C records borrow these; a deque never moves its
 * elements, so the pointers stay valid through digest + redeem. */
struct PkgxSrcHolder {
    std::string uri, suite;
    std::vector<std::string> components;
    std::vector<const char *> compp;
    std::vector<std::string> okeys, ovals;
    std::vector<const char *> okeyp, ovalp;
};
struct PkgxHoldHolder {
    std::string package, from, to;
    bool want_hold; /* the intended post-write selection, for the effector read-back */
};
struct PkgxCfgHolder {
    std::string package, arch, version, state;
};

/* apt.update: map the configured source list to the schema-1 source records — one per
 * (uri, suite) with its distinct components and the identity-relevant options. */
void pkgx_apt_map_sources(pkgSourceList &list, std::deque<PkgxSrcHolder> &holders,
                          std::vector<pkgx_src_record> &recs);

/* apt.hold / apt.unhold: read each target's current dpkg selection and keep only the
 * ones that actually change (an already-in-target transition is dropped). A target
 * absent from the cache is PKGX_HOLD_MAP_UNKNOWN; a target selected for anything but
 * install/hold is PKGX_HOLD_MAP_INVALID; `*offender` (when non-NULL) names it. `hold`
 * is true for apt.hold, false for apt.unhold. */
enum pkgx_hold_map {
    PKGX_HOLD_MAP_OK = 0,
    PKGX_HOLD_MAP_UNKNOWN,
    PKGX_HOLD_MAP_INVALID
};
pkgx_hold_map pkgx_apt_map_hold(pkgCache *cache, const char *const *targets,
                                size_t ntargets, bool hold,
                                std::deque<PkgxHoldHolder> &changes,
                                std::vector<pkgx_hold_record> &recs,
                                const char **offender);

/* apt.configure: enumerate the pending-configuration set (unpacked / half-configured
 * / triggers pending-or-awaited) into the schema-1 configure records. A half-installed
 * package is unrepairable by configure — PKGX_CFG_MAP_HALF_INSTALLED with `*name` (when
 * non-NULL) set to it, so the caller refuses BROKEN before the receipt is spent. */
enum pkgx_cfg_map {
    PKGX_CFG_MAP_OK = 0,
    PKGX_CFG_MAP_HALF_INSTALLED
};
pkgx_cfg_map pkgx_apt_map_configure(pkgCache *cache,
                                    std::deque<PkgxCfgHolder> &holders,
                                    std::vector<pkgx_cfg_record> &recs,
                                    const char **name);

/* A headless acquire status: no media swapping, no interactive prompts — the
 * only pure virtual of pkgAcquireStatus. */
class PkgxQuietAcquireStatus : public pkgAcquireStatus {
public:
    bool MediaChange(std::string, std::string) override {
        return false;
    }
};

/* dpkg ground truth after a commit: open a FRESH cache (the pre-commit dep cache
 * is stale) and report whether any package is left incomplete — unsatisfied
 * dependencies (pkgDepCache::BrokenCount) OR an incomplete dpkg state
 * (PkgIterator::State() != NeedsNothing, which covers unpacked / half-configured
 * / half-installed / triggers-pending-or-awaited / reinstall-required, the states
 * a failed maintainer script leaves with dependencies still satisfied). The fresh
 * read is isolated from any pre-existing libapt error stack, and an unreadable
 * cache is reported as broken (fail-safe: a caller that must reconcile treats the
 * unverifiable as the worse case). Shared by the transaction (A) and configure
 * (D) effectors — the two mechanisms whose commit runs dpkg and can leave the
 * database half-applied. */
bool pkgx_apt_ground_truth_broken();

/* The hold and configure committers drive dpkg through pkgx_spawn_wait (spawn.h). */

#endif /* PKGEXEC_APT_COMMON_HH */
