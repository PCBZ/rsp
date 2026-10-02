/* Start a command, feed it, drain it, reap it. Knows no JSON.
 *
 * Apart from gitleaks.c for the reason rsp/process.py is apart from the layers
 * above it: a pipe is not a report. In the other six adapters this is a
 * handful of lines from a standard library, which is why only this one has a
 * file for it. */
#ifndef RSP_SPAWN_H
#define RSP_SPAWN_H

#include <stddef.h>

/* Runs `argv` once with `input` on its stdin. On success writes the trimmed
 * stdout to `*out`, which the caller frees, and the exit status to `*status`;
 * returns -1 having written to stderr and reaped the child otherwise. */
int gl_spawn(char *const argv[], const char *input, size_t length, char **out, int *status);

#endif
