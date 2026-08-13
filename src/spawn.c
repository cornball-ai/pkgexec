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
         * process. The prior disposition is restored immediately after. */
        struct sigaction ign, old;
        memset(&ign, 0, sizeof ign);
        ign.sa_handler = SIG_IGN;
        sigemptyset(&ign.sa_mask);
        sigaction(SIGPIPE, &ign, &old);

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
            deliver_ok = 0; /* incomplete payload: the child did not take it all */
        }
        close(in[1]);
        sigaction(SIGPIPE, &old, NULL);
    }

    int status = 0;
    if (waitpid(pid, &status, 0) != pid) {
        return -1;
    }
    int exit_ok = (WIFEXITED(status) && WEXITSTATUS(status) == 0);
    return (exit_ok && deliver_ok) ? 0 : -1;
}
