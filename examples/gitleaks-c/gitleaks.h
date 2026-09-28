/* Wraps the gitleaks binary, through its `stdin` command and its report.
 *
 * Offsets are byte offsets into the content as the host sent it (S1), which a
 * char * gives for free — this is the one thing C makes easier than the other
 * four. What it makes harder is that nothing here can throw: every failure is
 * a return value, and a caller that ignores one carries on with garbage. */
#ifndef RSP_GITLEAKS_H
#define RSP_GITLEAKS_H

#include <cjson/cJSON.h>
#include <stddef.h>

/* Separates "found something" from gitleaks failing, which shares 1. */
#define GL_FOUND 2

/* Every entry point returns 0 on success and -1 having written to stderr. */

int gl_version(char **version);
int gl_scan(const char *content, size_t length, cJSON **findings);

/* The spans for one report, as a JSON array the caller owns. Returns -1 if any
 * finding could not be placed, which the caller turns into a BLOCK. */
int gl_to_spans(const cJSON *findings, const char *content, size_t length, cJSON **spans);

int gl_usable(long start, long end, const char *content, size_t length);

#endif
