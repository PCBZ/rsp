#include "protocol.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "gitleaks.h"

int rsp_escapes_a_nul(const char *raw) {
    for (const char *at = raw; *at; at++) {
        if (*at != '\\') continue;
        /* An even run of backslashes is escaped backslashes, not an escape. */
        size_t run = 1;
        while (at[run] == '\\') run++;
        if (run % 2 == 0) {
            at += run - 1;
            continue;
        }
        if (strncmp(at + run, "u0000", 5) == 0 || strncmp(at + run, "U0000", 5) == 0) return 1;
        at += run - 1;
    }
    return 0;
}

static cJSON *declare(void) {
    char *tool = NULL;
    if (gl_version(&tool) != 0) return NULL;

    char version[128];
    snprintf(version, sizeof version, "0.1.0+%s", tool);
    free(tool);

    cJSON *declaration = cJSON_CreateObject();
    cJSON *hooks = cJSON_CreateArray();
    if (!declaration || !hooks) {
        cJSON_Delete(declaration);
        cJSON_Delete(hooks);
        return NULL;
    }
    cJSON_AddItemToArray(hooks, cJSON_CreateString("on_chunk"));
    cJSON_AddItemToArray(hooks, cJSON_CreateString("on_retrieve"));
    cJSON_AddStringToObject(declaration, "rsp_version", "0.1");
    cJSON_AddStringToObject(declaration, "name", "rsp-gitleaks-c");
    /* The version carries the binary's: for a wrapper it is the tool that
     * decides verdicts, and the cache is keyed on this string (D4). */
    cJSON_AddStringToObject(declaration, "version", version);
    cJSON_AddItemToObject(declaration, "hooks", hooks);
    cJSON_AddBoolToObject(declaration, "deterministic", 1);
    return declaration;
}

static cJSON *verdict_only(const char *verdict) {
    cJSON *response = cJSON_CreateObject();
    if (response) cJSON_AddStringToObject(response, "verdict", verdict);
    return response;
}

static cJSON *blocked(const char *reason) {
    cJSON *response = verdict_only("BLOCK");
    if (response) {
        cJSON_AddStringToObject(response, "reason", reason);
        cJSON_AddStringToObject(response, "severity", "critical");
    }
    return response;
}

cJSON *rsp_respond(const cJSON *request, const char *raw) {
    const cJSON *hook = cJSON_GetObjectItemCaseSensitive(request, "hook");
    if (cJSON_IsString(hook) && strcmp(hook->valuestring, "handshake") == 0) return declare();

    if (rsp_escapes_a_nul(raw)) {
        fprintf(stderr, "rsp-gitleaks-c: a chunk holding a NUL cannot be judged here\n");
        return NULL;
    }

    const cJSON *item = cJSON_GetObjectItemCaseSensitive(request, "content");
    const char *content = cJSON_IsString(item) ? item->valuestring : "";
    size_t length = strlen(content);

    cJSON *findings = NULL;
    if (gl_scan(content, length, &findings) != 0) return NULL;
    /* ALLOW carries nothing else: the common case is the cheap one (V2). */
    if (cJSON_GetArraySize(findings) == 0) {
        cJSON_Delete(findings);
        return verdict_only("ALLOW");
    }

    cJSON *spans = NULL;
    int placed = gl_to_spans(findings, content, length, &spans);
    cJSON_Delete(findings);
    /* A finding with no span is a secret we cannot point at; redacting the
     * rest would leave it in the chunk (V4). */
    if (placed != 0) {
        return blocked("gitleaks reported a finding whose position could not be confirmed");
    }

    cJSON *response = verdict_only("REDACT");
    if (!response) {
        cJSON_Delete(spans);
        return NULL;
    }
    cJSON_AddItemToObject(response, "spans", spans);
    cJSON_AddStringToObject(response, "replacement", RSP_REPLACEMENT);
    cJSON_AddStringToObject(response, "severity", "critical");
    return response;
}
