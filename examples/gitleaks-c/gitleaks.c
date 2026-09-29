#include "gitleaks.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "spawn.h"

static const char *binary(void) {
    const char *override = getenv("RSP_GITLEAKS");
    return (override && *override) ? override : "gitleaks";
}

/* 0 or GL_FOUND and nothing else: gitleaks shares 1 between "found" and
 * "failed", so a status this does not know is a run that cannot be read. */
static int accepted(int status, char **report) {
    if (status == 0 || status == GL_FOUND) return 0;
    fprintf(stderr, "rsp-gitleaks-c: gitleaks exited with %d\n", status);
    free(*report);
    *report = NULL;
    return -1;
}

int gl_version(char **version) {
    char *argv[] = {(char *)binary(), "version", NULL};
    int status = 0;
    if (gl_spawn(argv, "", 0, version, &status) != 0) return -1;
    return accepted(status, version);
}

int gl_scan(const char *content, size_t length, cJSON **findings) {
    /* "-" is gitleaks' own spelling of stdout; /dev/stdout fails its
     * writability pre-check. --no-banner keeps stdout to the report alone. */
    char *argv[] = {(char *)binary(), "stdin", "--no-banner", "--report-format", "json",
                    "--report-path", "-",     "--exit-code",  "2",               NULL};
    char *report = NULL;
    int status = 0;
    if (gl_spawn(argv, content, length, &report, &status) != 0) return -1;
    if (accepted(status, &report) != 0) return -1;

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
