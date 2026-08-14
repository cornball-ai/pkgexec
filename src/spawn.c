/* See spawn.h. */
#include "spawn.h"

#include <errno.h>
#include <signal.h>
#include <spawn.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

/* Build a child environment = the extra_env entries (first, so they take
 * precedence over any inherited duplicate) followed by the inherited environ,
 * NUL-terminated. Returns a malloc'd pointer array the caller frees; the entries
 * themselves are borrowed (not copied), which is enough — posix_spawn consumes the
 * array during the call and the child gets its own copy. NULL on allocation
 * failure (the caller then fails closed). */
static char **build_child_env(const char *const extra_env[]) {
    size_t nextra = 0;
    while (extra_env[nextra] != NULL) {
        nextra++;
    }
    size_t nenv = 0;
    while (environ[nenv] != NULL) {
        nenv++;
    }
    char **envp = malloc((nextra + nenv + 1) * sizeof *envp);
    if (envp == NULL) {
        return NULL;
    }
    size_t k = 0;
    for (size_t i = 0; i < nextra; i++) {
        envp[k++] = (char *) extra_env[i];
    }
    for (size_t i = 0; i < nenv; i++) {
        envp[k++] = environ[i];
    }
    envp[k] = NULL;
    return envp;
}

int pkgx_spawn_wait_env(const char *const argv[], const char *input,
                        const char *const extra_env[], int *started) {
    if (started != NULL) {
        *started = 0; /* no child yet; set to 1 only once posix_spawn succeeds */
    }
    if (argv == NULL || argv[0] == NULL) {
        return -1;
    }

    /* The child environment: the inherited environ, plus any extra_env entries —
     * added to the CHILD only, never to this process's environment. Built before
     * the pipe/spawn setup so an allocation failure fails closed with nothing
     * started. When there is nothing extra, the inherited environ is passed
     * directly (no allocation). */
    char **built_env = NULL;
    char **child_env = environ;
    if (extra_env != NULL) {
        built_env = build_child_env(extra_env);
        if (built_env == NULL) {
            return -1;
        }
        child_env = built_env;
    }

    int in[2] = {-1, -1};
    if (input != NULL && pipe(in) != 0) {
        free(built_env);
        return -1;
    }

    posix_spawn_file_actions_t fa;
    if (posix_spawn_file_actions_init(&fa) != 0) {
        if (input != NULL) {
            close(in[0]);
            close(in[1]);
        }
        free(built_env);
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
            free(built_env);
            return -1;
        }
    }

    pid_t pid = 0;
    int sp = posix_spawn(&pid, argv[0], &fa, NULL,
                         (char *const *) argv, child_env);
    posix_spawn_file_actions_destroy(&fa);
    free(built_env); /* the child has its own environment copy now */
    if (input != NULL) {
        close(in[0]); /* the child owns the read end now */
    }
    if (sp != 0) {
        if (input != NULL) {
            close(in[1]);
        }
        return -1;
    }
    if (started != NULL) {
        *started = 1; /* the child exists; from here the host may be mutated */
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

int pkgx_spawn_wait(const char *const argv[], const char *input, int *started) {
    return pkgx_spawn_wait_env(argv, input, NULL, started);
}
