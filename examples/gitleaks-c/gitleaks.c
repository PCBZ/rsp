/* fork, execvp, poll, kill and waitpid are POSIX, and -std=c11 tells glibc
 * to hide what ISO C does not define. Said here rather than in CFLAGS so a
 * build that overrides those still compiles. */
#define _POSIX_C_SOURCE 200809L

#include "gitleaks.h"

#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static const char *binary(void) {
    const char *override = getenv("RSP_GITLEAKS");
    return (override && *override) ? override : "gitleaks";
}

/* Runs the binary once, returning what it wrote and how it exited.
 *
 * Both directions are polled. Writing the chunk and then reading the report
 * would deadlock against a tool that fills the stdout pipe before draining
 * stdin; Go and Node do this for you and Rust spawns a thread, but here it is
 * the loop below. */
static int run(char *const argv[], const char *input, size_t length, char **out, int *status) {
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

    size_t written = 0, held = 0, room = 8192;
    char *report = malloc(room);
    if (!report) {
        close(to_child[1]);
        close(from_child[0]);
        return -1;
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
            if (sent <= 0 || (written += (size_t)sent) == length) {
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
    report[held] = '\0';

    int wait_status = 0;
    if (waitpid(child, &wait_status, 0) < 0) {
        free(report);
        return -1;
    }
    *status = WIFEXITED(wait_status) ? WEXITSTATUS(wait_status) : -1;
    if (*status != 0 && *status != GL_FOUND) {
        fprintf(stderr, "rsp-gitleaks-c: gitleaks exited with %d\n", *status);
        free(report);
        return -1;
    }
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

int gl_version(char **version) {
    char *argv[] = {(char *)binary(), "version", NULL};
    int status = 0;
    return run(argv, "", 0, version, &status);
}

int gl_scan(const char *content, size_t length, cJSON **findings) {
    /* "-" is gitleaks' own spelling of stdout; /dev/stdout fails its
     * writability pre-check. --no-banner keeps stdout to the report alone. */
    char *argv[] = {(char *)binary(), "stdin", "--no-banner", "--report-format", "json",
                    "--report-path", "-",     "--exit-code",  "2",               NULL};
    char *report = NULL;
    int status = 0;
    if (run(argv, content, length, &report, &status) != 0) return -1;

    /* Exit 0 with nothing written is a clean chunk. Exit 2 is gitleaks saying
     * it found something, so nothing written is a report that went missing,
     * and reading it as no findings is the ALLOW E1 refuses. */
    if (status == GL_FOUND && *report == '\0') {
        fprintf(stderr, "rsp-gitleaks-c: gitleaks reported findings and wrote no report\n");
        free(report);
        return -1;
    }
    *findings = (*report == '\0') ? cJSON_CreateArray() : cJSON_Parse(report);
    free(report);
    if (!*findings || !cJSON_IsArray(*findings)) {
        fprintf(stderr, "rsp-gitleaks-c: gitleaks wrote a report that is not a list\n");
        cJSON_Delete(*findings);
        return -1;
    }
    return 0;
}

int gl_usable(long start, long end, const char *content, size_t length) {
    if (start < 0 || end <= start || (size_t)end > length) return 0;
    /* A continuation byte is 0b10xxxxxx; a boundary is anything else. */
    long edges[2] = {start, end};
    for (int i = 0; i < 2; i++) {
        size_t at = (size_t)edges[i];
        if (at != 0 && at != length && (content[at] & 0xC0) == 0x80) return 0;
    }
    return 1;
}

/* The byte gitleaks counts this line's columns from, or -1 if the content has
 * no such line. Its columns run from the newline that ended the previous line,
 * not from the line's first byte, so only line one matches the 1-based column
 * anyone assumes. */
static long origin(const char *content, size_t length, long line) {
    if (line == 1) return 0;
    if (line < 1) return -1;
    long seen = 1;
    for (size_t at = 0; at < length; at++) {
        if (content[at] != '\n') continue;
        if (++seen == line) return (long)at;
    }
    return -1;
}

static long number(const cJSON *object, const char *name) {
    const cJSON *item = cJSON_GetObjectItemCaseSensitive(object, name);
    return cJSON_IsNumber(item) ? (long)item->valuedouble : 0;
}

static const char *text(const cJSON *object, const char *name) {
    const cJSON *item = cJSON_GetObjectItemCaseSensitive(object, name);
    return cJSON_IsString(item) ? item->valuestring : "";
}

int gl_to_spans(const cJSON *findings, const char *content, size_t length, cJSON **spans) {
    *spans = cJSON_CreateArray();
    if (!*spans) return -1;

    const cJSON *finding = NULL;
    cJSON_ArrayForEach(finding, findings) {
        /* EndColumn belongs to EndLine, which differs whenever a finding spans
         * lines. Anything that does not slice Match back out is refused, and
         * the caller turns that into a BLOCK. */
        long from = origin(content, length, number(finding, "StartLine"));
        long to = origin(content, length, number(finding, "EndLine"));
        long start = from + number(finding, "StartColumn") - 1;
        long end = to + number(finding, "EndColumn");
        const char *match = text(finding, "Match");

        if (from < 0 || to < 0 || !gl_usable(start, end, content, length) ||
            strlen(match) != (size_t)(end - start) ||
            memcmp(content + start, match, (size_t)(end - start)) != 0) {
            cJSON_Delete(*spans);
            *spans = NULL;
            return -1;
        }
        cJSON *span = cJSON_CreateObject();
        if (!span || !cJSON_AddNumberToObject(span, "start", (double)start) ||
            !cJSON_AddNumberToObject(span, "end", (double)end) ||
            !cJSON_AddStringToObject(span, "type", text(finding, "RuleID")) ||
            !cJSON_AddItemToArray(*spans, span)) {
            cJSON_Delete(span);
            cJSON_Delete(*spans);
            *spans = NULL;
            return -1;
        }
    }
    return 0;
}
