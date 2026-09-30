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

/* Past a string literal, which is where a digit means nothing. */
static const char *past_string(const char *at) {
    for (at++; *at && *at != '"'; at++) {
        if (*at == '\\' && at[1]) at++;
    }
    return *at ? at + 1 : at;
}

int rsp_strict_text(const char *raw) {
    if ((unsigned char)raw[0] == 0xEF && (unsigned char)raw[1] == 0xBB
        && (unsigned char)raw[2] == 0xBF) {
        return refuse("a byte order mark is not whitespace");
    }
    for (const char *at = raw; *at; ) {
        if (*at == '"') {
            at = past_string(at);
            continue;
        }
        if ((*at == '-' || (*at >= '0' && *at <= '9'))
            && (at == raw || strchr(":,[ \t\n\r", at[-1]))) {
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

/* Asked of the tree, not the text: cJSON keeps both of a repeated key as
 * siblings and has already unescaped them, so two spellings of one name
 * arrive here as one name twice. A text scan comparing what was written sees
 * two different keys and lets the message through. */
int rsp_strict_tree(const cJSON *value) {
    if (cJSON_IsObject(value)) {
        for (const cJSON *one = value->child; one; one = one->next) {
            for (const cJSON *other = one->next; other; other = other->next) {
                if (one->string && other->string && strcmp(one->string, other->string) == 0) {
                    return refuse("a key is repeated in one object");
                }
            }
        }
    }
    for (const cJSON *child = value->child; child; child = child->next) {
        if (rsp_strict_tree(child) != 0) return -1;
    }
    return 0;
}
