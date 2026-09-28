/* One JSON object in, one out, then exit (T1).
 *
 * Diagnostics go to stderr: a stray line on stdout is indistinguishable from a
 * response (T2). Every failure below exits non-zero having written nothing to
 * stdout, which is how a plugin says it could not judge the chunk (E1, D3). */
#include <cjson/cJSON.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "protocol.h"

static char *read_all(void) {
    size_t held = 0, room = 8192;
    char *buffer = malloc(room);
    if (!buffer) return NULL;
    for (;;) {
        ssize_t got = read(STDIN_FILENO, buffer + held, room - held - 1);
        if (got < 0) {
            free(buffer);
            return NULL;
        }
        if (got == 0) break;
        held += (size_t)got;
        if (held + 4096 > room) {
            char *bigger = realloc(buffer, room * 2);
            if (!bigger) {
                free(buffer);
                return NULL;
            }
            buffer = bigger;
            room *= 2;
        }
    }
    buffer[held] = '\0';
    return buffer;
}

int main(void) {
    char *raw = read_all();
    if (!raw) {
        fprintf(stderr, "rsp-gitleaks-c: could not read the request\n");
        return 1;
    }
    cJSON *request = cJSON_Parse(raw);
    if (!request) {
        fprintf(stderr, "rsp-gitleaks-c: the request is not JSON\n");
        free(raw);
        return 1;
    }

    cJSON *response = rsp_respond(request, raw);
    cJSON_Delete(request);
    free(raw);
    if (!response) return 1;

    char *text = cJSON_PrintUnformatted(response);
    cJSON_Delete(response);
    if (!text) return 1;
    printf("%s\n", text);
    free(text);
    return 0;
}
