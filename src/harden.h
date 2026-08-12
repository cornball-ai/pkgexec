/* Process hygiene for the effector entrypoints: read the trusted invoking uid,
 * scrub the inherited environment to a fixed allowlist, and keep inherited file
 * descriptors from leaking to children. Slice 1 spawns no children and takes no
 * lock; these are the primitives later slices call before dpkg runs, unit-tested
 * here in isolation. */
#ifndef PKGEXEC_HARDEN_H
#define PKGEXEC_HARDEN_H

#include <sys/types.h> /* uid_t */

/* Read PKEXEC_UID from the trusted (pkexec-set) environment. MUST be called
 * before pkgx_scrub_env(), which erases it. Returns 0 and sets *uid on a
 * well-formed non-negative integer that fits uid_t, -1 otherwise (absent,
 * empty, non-numeric, or out of range). */
int pkgx_read_pkexec_uid(uid_t *uid);

/* Replace the environment with a fixed minimal allowlist:
 *   PATH=/usr/sbin:/usr/bin:/sbin:/bin, LC_ALL=C, DEBIAN_FRONTEND=noninteractive.
 * Everything inherited (APT_CONFIG, DPKG_*, LD_*, *_proxy, ...) is dropped.
 * Returns 0 on success, -1 on failure. */
int pkgx_scrub_env(void);

/* Set close-on-exec on every open descriptor at or above `lowest`, so no
 * inherited fd (a lingering request pipe, a broker socket) survives an exec into
 * a child. Descriptors below `lowest` (typically 0/1/2) are left alone. Returns
 * 0 on success, -1 on failure. */
int pkgx_cloexec_from(int lowest);

/* Replace fd 0 with /dev/null (read-only), so a child can neither read a
 * lingering request/receipt on stdin nor block on an interactive prompt.
 * Returns 0 on success, -1 on failure. */
int pkgx_null_stdin(void);

#endif /* PKGEXEC_HARDEN_H */
