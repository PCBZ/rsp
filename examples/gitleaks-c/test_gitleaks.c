/* Line-and-column to byte offsets, and what only this language gets wrong.
 *
 * The table is examples/gitleaks-offsets.json, shared with the other six
 * adapters, because the numbers in it are facts about gitleaks rather than
 * about any of them. No binary is needed: a report is data. */
#include <cjson/cJSON.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "gitleaks.h"
#include "protocol.h"

static int failures = 0;

static void check(int held, const char *what) {
    if (!held) {
        fprintf(stderr, "FAIL %s\n", what);
        failures++;
    }
}

static char *slurp(const char *path) {
    FILE *file = fopen(path, "rb");
    if (!file) return NULL;
    fseek(file, 0, SEEK_END);
    long size = ftell(file);
    rewind(file);
    char *text = malloc((size_t)size + 1);
    if (text && fread(text, 1, (size_t)size, file) != (size_t)size) {
        free(text);
        text = NULL;
    }
    if (text) text[size] = '\0';
    fclose(file);
    return text;
}

static void the_shared_table(void) {
    char *raw = slurp("../gitleaks-offsets.json");
    check(raw != NULL, "the shared table is where it is expected");
    if (!raw) return;

    cJSON *table = cJSON_Parse(raw);
    free(raw);
    check(table != NULL, "the shared table parses");
    if (!table) return;

    const cJSON *tests = cJSON_GetObjectItemCaseSensitive(table, "tests");
    /* A path that resolved to nothing would leave this loop empty and green. */
    check(cJSON_GetArraySize(tests) >= 13, "the table did not lose cases");

    const cJSON *test = NULL;
    cJSON_ArrayForEach(test, tests) {
        const char *content = cJSON_GetStringValue(cJSON_GetObjectItem(test, "content"));
        const char *comment = cJSON_GetStringValue(cJSON_GetObjectItem(test, "comment"));
        const cJSON *findings = cJSON_GetObjectItemCaseSensitive(test, "findings");
        const cJSON *want = cJSON_GetObjectItemCaseSensitive(test, "spans");

        cJSON *got = NULL;
        int placed = gl_to_spans(findings, content, strlen(content), &got);

        if (cJSON_GetArraySize(want) == 0 && cJSON_GetArraySize(findings) > 0) {
            check(placed != 0, comment); /* every case that expects no spans */
        } else {
            check(placed == 0 && got && cJSON_Compare(got, want, 1), comment);
        }
        cJSON_Delete(got);
    }
    cJSON_Delete(table);
}

static void a_nul_is_refused(void) {
    /* cJSON hands back a char *, so content holding a NUL arrives shorter than
     * the host sent it. The offsets would then index the truncated text while
     * the host applies them to the whole, redacting the wrong bytes. */
    check(rsp_escapes_a_nul("{\"content\":\"a\\u0000b\"}"), "an escaped NUL is seen");
    check(rsp_escapes_a_nul("{\"content\":\"a\\\\u0000b\"}") == 0,
          "an escaped backslash before u0000 is not one");
    check(rsp_escapes_a_nul("{\"content\":\"a\\\\\\u0000b\"}"), "three backslashes are one escape");
    check(rsp_escapes_a_nul("{\"content\":\"plain\"}") == 0, "ordinary content is not one");
}

static void a_match_shorter_than_its_span(void) {
    /* Refused on length before memcmp reads it. The comparison alone would run
     * past Match's terminator, which no assertion here can see and the
     * sanitizer in CI can — this case exists to give it something to see. */
    const char *content = "AKIALALEMEL33243OLIB";
    cJSON *findings = cJSON_Parse("[{\"RuleID\":\"aws-access-token\",\"StartLine\":1,"
                                  "\"EndLine\":1,\"StartColumn\":1,\"EndColumn\":20,"
                                  "\"Match\":\"AKIA\"}]");
    check(findings != NULL, "the short-match report parses");

    cJSON *spans = NULL;
    check(gl_to_spans(findings, content, strlen(content), &spans) != 0,
          "a Match shorter than its span is refused");
    cJSON_Delete(spans);
    cJSON_Delete(findings);
}

static void spans_the_host_would_reject(void) {
    const char *content = "密钥 AKIALALEMEL33243OLIB";
    size_t length = strlen(content);

    check(gl_usable(1, 3, content, length) == 0, "offsets inside a character are refused");
    check(gl_usable(0, 0, content, length) == 0, "an empty span is refused");
    check(gl_usable(-1, 5, content, length) == 0, "a negative start is refused");
    check(gl_usable(7, 400, content, length) == 0, "an end past the content is refused");
    check(gl_usable(7, 27, content, length), "the key itself is usable");
}

int main(void) {
    the_shared_table();
    a_nul_is_refused();
    a_match_shorter_than_its_span();
    spans_the_host_would_reject();
    if (failures) {
        fprintf(stderr, "%d failed\n", failures);
        return 1;
    }
    printf("ok\n");
    return 0;
}
