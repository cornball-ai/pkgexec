/* Spawn a program with an explicit argv (no shell), optionally delivering a
 * complete stdin payload, and wait for it. The hold and configure committers
 * drive dpkg through this. It fails closed: any posix_spawn setup error, a
 * child that exits non-zero, a child that closes its stdin before the whole
 * payload is delivered, or a write error all return non-zero. Writing to the
 * child cannot raise SIGPIPE in this process (the signal is ignored for the
 * duration of the write and restored after). Pure POSIX — no libapt — so it is
 * unit-tested on its own. */
#ifndef PKGEXEC_SPAWN_H
#define PKGEXEC_SPAWN_H

#ifdef __cplusplus
extern "C" {
#endif

/* Run argv[0] (an absolute path) with argv, feeding `input` (if non-NULL) to
 * its stdin in full. Returns 0 iff the child exited 0 AND, when input was
 * given, the entire payload was delivered; -1 otherwise.
 *
 * If `started` is non-NULL it is set to 1 iff the child process was actually
 * created (posix_spawn succeeded), else 0 — distinct from the return value, so a
 * caller can tell "dpkg ran and failed" (started=1, returns -1) from "dpkg never
 * ran" (started=0). This is the `effect_issued` truth for the shelled mechanisms:
 * the host may have been mutated iff the child started. */
int pkgx_spawn_wait(const char *const argv[], const char *input, int *started);

/* As pkgx_spawn_wait, but the child additionally receives each "KEY=VALUE" entry of
 * `extra_env` (a NULL-terminated array, or NULL for none) in its environment — and
 * ONLY the child: the calling process's environment is never modified. The hold and
 * configure committers use it to give the spawned dpkg DPKG_FRONTEND_LOCKED=true
 * (the effector holds the outer frontend lock, so dpkg must skip it and take only
 * the inner lock the effector released) without leaking that flag into the ambient
 * environment. Entries precede the inherited environment, so they take precedence. */
int pkgx_spawn_wait_env(const char *const argv[], const char *input,
                        const char *const extra_env[], int *started);

#ifdef __cplusplus
}
#endif

#endif /* PKGEXEC_SPAWN_H */
