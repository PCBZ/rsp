/* fork, execvp, poll, kill and waitpid are POSIX, and -std=c11 tells glibc
 * to hide what ISO C does not define. Said here rather than in CFLAGS so a
 * build that overrides those still compiles. */
#define _POSIX_C_SOURCE 200809L

#include "spawn.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

/* Runs the binary once, returning what it wrote and how it exited.
 *
 * Both directions are polled. Writing the chunk and then reading the report
 * would deadlock against a tool that fills the stdout pipe before draining
 * stdin; Go and Node do this for you and Rust spawns a thread, but here it is
 * the loop below. */
int gl_spawn(char *const argv[], const char *input, size_t length, char **out, int *status) {
    int to_child[2], from_child[2];
    if (pipe(to_child) != 0 || pipe(from_child) != 0) {
        perror("rsp-gitleaks-c: pipe");
        return -1;
    }

    pid_t child = fork();
    if (child < 0) {
        perror("rsp-gitleaks-c: fork");
        return -1;
    }
    if (child == 0) {
        dup2(to_child[0], STDIN_FILENO);
        dup2(from_child[1], STDOUT_FILENO);
        close(to_child[1]);
        close(from_child[0]);
        execvp(argv[0], argv);
        _exit(127); /* exec failed; the parent sees the status */
    }
    close(to_child[0]);
    close(from_child[1]);
    signal(SIGPIPE, SIG_IGN); /* a tool that exits early must not kill us */
    /* Non-blocking, or the poll below is not enough: POLLOUT means some room,
     * and a blocking write of more than that waits for the child to take all
     * of it — which it cannot while its own stdout is full. */
    fcntl(to_child[1], F_SETFL, O_NONBLOCK);

    size_t written = 0, held = 0, room = 8192;
    char *report = malloc(room);
    if (!report) goto giving_up; /* which reaps the child this used to abandon */
    if (length == 0) { /* nothing to send, and a zero-length write says nothing */
        close(to_child[1]);
        to_child[1] = -1;
    }

    /* Every failure below leaves through `giving_up`, because the ones that do
     * not are what turns half a report into a verdict. */
    while (from_child[0] >= 0) {
        struct pollfd fds[2] = {{from_child[0], POLLIN, 0}, {to_child[1], POLLOUT, 0}};
        int watching = (to_child[1] >= 0) ? 2 : 1;
        if (poll(fds, watching, -1) < 0) {
            /* revents is undefined after a failed poll, so neither branch below
             * may run on the way past. */
            if (errno == EINTR) continue;
            perror("rsp-gitleaks-c: poll");
            goto giving_up;
        }

        if (watching == 2 && (fds[1].revents & (POLLOUT | POLLERR | POLLHUP))) {
            ssize_t sent = write(to_child[1], input + written, length - written);
            if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) {
                continue; /* no room yet, or interrupted: the poll will say when */
            }
            if (sent > 0) written += (size_t)sent;
            if (sent <= 0 || written == length) {
                /* Whether the chunk got there is settled after the loop: a
                 * child that stopped reading judged less than we sent. */
                close(to_child[1]);
                to_child[1] = -1;
            }
        }
        if (fds[0].revents & (POLLIN | POLLHUP)) {
            if (held + 4096 > room) {
                char *bigger = realloc(report, room * 2);
                if (!bigger) goto giving_up; /* realloc into itself loses this */
                report = bigger;
                room *= 2;
            }
            ssize_t got = read(from_child[0], report + held, room - held - 1);
            if (got < 0) {
                if (errno == EINTR) continue;
                perror("rsp-gitleaks-c: read");
                goto giving_up;
            }
            if (got == 0) { /* EOF, which -1 is not */
                close(from_child[0]);
                from_child[0] = -1;
            } else {
                held += (size_t)got;
            }
        }
    }
    if (to_child[1] >= 0) close(to_child[1]);
    if (written != length) {
        /* The tool saw part of the chunk, so its verdict is not about ours —
         * whatever its exit status says (E1). */
        fprintf(stderr, "rsp-gitleaks-c: sent %zu of %zu bytes\n", written, length);
        goto giving_up;
    }
    report[held] = '\0';

    int wait_status = 0;
    if (waitpid(child, &wait_status, 0) < 0) {
        free(report);
        return -1;
    }
    /* Reported, not judged: which statuses are acceptable is the wrapped
     * tool's convention, and this layer knows of no tool. A signal is -1,
     * which no exit status is. */
    *status = WIFEXITED(wait_status) ? WEXITSTATUS(wait_status) : -1;
    while (held > 0 && (report[held - 1] == '\n' || report[held - 1] == ' ')) report[--held] = '\0';
    *out = report;
    return 0;

giving_up:
    free(report);
    if (to_child[1] >= 0) close(to_child[1]);
    if (from_child[0] >= 0) close(from_child[0]);
    kill(child, SIGKILL); /* else waitpid blocks on a tool still writing */
    while (waitpid(child, NULL, 0) < 0 && errno == EINTR) {}
    return -1;
}
