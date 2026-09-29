/* One message, refusing what a lenient parser would take (T4).
 *
 * cJSON refuses NaN and an unpaired surrogate. What it takes and T4 does not:
 * a repeated key, an integer JavaScript would round, a leading zero, and a
 * byte order mark. None of those is visible after parsing — cJSON keeps the
 * first of two equal keys and hands back a double — so this reads the text. */
#ifndef RSP_STRICT_H
#define RSP_STRICT_H

/* 0 if the message is one the grammar allows, -1 having written to stderr. */
int rsp_strict(const char *raw);

#endif
