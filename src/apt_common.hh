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

/* Spawn a program (no shell) with an explicit argv, optionally feeding `input`
 * to its stdin, and wait. Returns 0 iff it exited 0. argv is NULL-terminated;
 * argv[0] must be an absolute path. Used by the hold and configure committers,
 * which drive dpkg directly. */
int pkgx_spawn_wait(const char *const argv[], const char *input);

#endif /* PKGEXEC_APT_COMMON_HH */
