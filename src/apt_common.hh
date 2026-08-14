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
