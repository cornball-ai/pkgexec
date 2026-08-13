/* See spawn.h. */
#include "spawn.h"

#include <errno.h>
#include <signal.h>
#include <spawn.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

int pkgx_spawn_wait(const char *const argv[], const char *input) {
    if (argv == NULL || argv[0] == NULL) {
        return -1;
    }
    int in[2] = {-1, -1};
    if (input != NULL && pipe(in) != 0) {
        return -1;
    }

    posix_spawn_file_actions_t fa;
    if (posix_spawn_file_actions_init(&fa) != 0) {
        if (input != NULL) {
            close(in[0]);
            close(in[1]);
        }
        return -1;
    }
    if (input != NULL) {
        /* Every file-action result is checked: a silent failure here would let
         * the child run with the wrong stdin. */
        if (posix_spawn_file_actions_adddup2(&fa, in[0], STDIN_FILENO) != 0 ||
            posix_spawn_file_actions_addclose(&fa, in[0]) != 0 ||
            posix_spawn_file_actions_addclose(&fa, in[1]) != 0) {
            posix_spawn_file_actions_destroy(&fa);
            close(in[0]);
            close(in[1]);
            return -1;
        }
    }

    pid_t pid = 0;
    int sp = posix_spawn(&pid, argv[0], &fa, NULL,
                         (char *const *) argv, environ);
    posix_spawn_file_actions_destroy(&fa);
    if (input != NULL) {
        close(in[0]); /* the child owns the read end now */
    }
    if (sp != 0) {
        if (input != NULL) {
            close(in[1]);
        }
        return -1;
    }

    int deliver_ok = 1;
    if (input != NULL) {
        /* Ignore SIGPIPE only for the write: a child that closes its stdin
         * early then yields EPIPE (a failure we detect) instead of killing this
         * process. If the handler cannot be installed, `old` is undefined and a
         * write could still raise SIGPIPE — so fail closed and do not write. */
        struct sigaction ign, old;
        memset(&ign, 0, sizeof ign);
        ign.sa_handler = SIG_IGN;
        sigemptyset(&ign.sa_mask);
        if (sigaction(SIGPIPE, &ign, &old) != 0) {
            deliver_ok = 0;
            close(in[1]);
        } else {
            size_t len = strlen(input);
            size_t off = 0;
            while (off < len) {
                ssize_t w = write(in[1], input + off, len - off);
                if (w < 0) {
                    if (errno == EINTR) {
                        continue;
                    }
                    break; /* EPIPE (child closed) or other error */
                }
                if (w == 0) {
                    break;
                }
                off += (size_t) w;
            }
            if (off != len) {
                deliver_ok = 0; /* incomplete payload: the child took only part */
            }
            close(in[1]);
            /* Restoration failing leaves this process's SIGPIPE disposition
             * wrong; a one-shot helper is about to exit, but treat the fault as
             * a failure so the caller reconciles rather than trusts the result. */
            if (sigaction(SIGPIPE, &old, NULL) != 0) {
                deliver_ok = 0;
            }
        }
    }

    int status = 0;
    pid_t w;
    do {
        w = waitpid(pid, &status, 0);
    } while (w < 0 && errno == EINTR);
    if (w != pid) {
        return -1;
    }
    int exit_ok = (WIFEXITED(status) && WEXITSTATUS(status) == 0);
    return (exit_ok && deliver_ok) ? 0 : -1;
}
