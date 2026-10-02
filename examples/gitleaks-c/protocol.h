/* The shape SPEC.md requires, in one file, for whoever ports this again. */
#ifndef RSP_PROTOCOL_H
#define RSP_PROTOCOL_H

#include <cjson/cJSON.h>

#define RSP_REPLACEMENT "[REDACTED:secret]"

/* The response to one request, which the caller owns, or NULL having written
 * to stderr. A plugin reports failure by failing; the host turns that into a
 * verdict (E1, D3). */
cJSON *rsp_respond(const cJSON *request, const char *raw);

/* Whether the raw request escapes a NUL inside a string.
 *
 * cJSON hands back a char *, which stops at the first NUL, so content holding
 * one arrives here shorter than the host sent. The offsets gitleaks then
 * reports index the truncated text and the host applies them to the whole,
 * which redacts the wrong bytes rather than missing a secret. Refused instead:
 * this plugin cannot represent that chunk, and saying so is the only honest
 * answer (E1). The other six adapters carry a length and are unaffected. */
int rsp_escapes_a_nul(const char *raw);

#endif
