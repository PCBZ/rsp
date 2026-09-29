#include "strict.h"

#include <stdio.h>
#include <string.h>

/* The largest a JavaScript number carries exactly, as digits: comparing text
 * avoids asking what this platform's long can hold. */
#define SAFE_INTEGER "9007199254740991"

static int refuse(const char *why) {
    fprintf(stderr, "rsp-gitleaks-c: %s\n", why);
    return -1;
}

/* Past a string literal, which is where a brace or a digit means nothing. */
static const char *past_string(const char *at) {
    for (at++; *at && *at != '"'; at++) {
        if (*at == '\\' && at[1]) at++;
    }
    return *at ? at + 1 : at;
}

/* Whether this key has been seen in the object depth `depth` is tracking.
 * Keys are compared as written: two spellings of one key are two keys to
 * every parser, so the grammar's question is the textual one. */
static int repeated(const char *raw, const char *key, size_t length, int depth) {
    int at_depth = 0;
    for (const char *scan = raw; *scan; ) {
        if (*scan == '"') {
            const char *end = past_string(scan);
            const char *after = end;
            while (*after == ' ' || *after == '\t' || *after == '\n' || *after == '\r') after++;
            if (*after == ':' && at_depth == depth && (size_t)(end - scan - 2) == length
                && strncmp(scan + 1, key, length) == 0) {
                if (scan + 1 != key) return 1;
            }
            scan = end;
            continue;
        }
        if (*scan == '{') at_depth++;
        if (*scan == '}') at_depth--;
        scan++;
    }
    return 0;
}

int rsp_strict(const char *raw) {
    if ((unsigned char)raw[0] == 0xEF && (unsigned char)raw[1] == 0xBB
        && (unsigned char)raw[2] == 0xBF) {
        return refuse("a byte order mark is not whitespace");
    }
    int depth = 0;
    for (const char *at = raw; *at; ) {
        if (*at == '"') {
            const char *end = past_string(at);
            const char *after = end;
            while (*after == ' ' || *after == '\t' || *after == '\n' || *after == '\r') after++;
            if (*after == ':' && repeated(raw, at + 1, (size_t)(end - at - 2), depth)) {
                return refuse("a key is repeated in one object");
            }
            at = end;
            continue;
        }
        if (*at == '{') depth++;
        if (*at == '}') depth--;
        if ((*at == '-' || (*at >= '0' && *at <= '9')) && (at == raw || strchr(":,[ \t\n\r", at[-1]))) {
            const char *digits = (*at == '-') ? at + 1 : at;
            size_t run = strspn(digits, "0123456789");
            if (run > 1 && digits[0] == '0') return refuse("a number may not have a leading zero");
            if (digits[run] != '.' && digits[run] != 'e' && digits[run] != 'E'
                && (run > strlen(SAFE_INTEGER)
                    || (run == strlen(SAFE_INTEGER) && strncmp(digits, SAFE_INTEGER, run) > 0))) {
                return refuse("an integer outside the safe range");
            }
            at = digits + run;
            continue;
        }
        at++;
    }
    return 0;
}
