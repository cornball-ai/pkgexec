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
 * given, the entire payload was delivered; -1 otherwise. */
int pkgx_spawn_wait(const char *const argv[], const char *input);

#ifdef __cplusplus
}
#endif

#endif /* PKGEXEC_SPAWN_H */
