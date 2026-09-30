/* One message, refusing what a lenient parser would take (T4).
 *
 * Split in two because the leniencies are: cJSON keeps both of a repeated key
 * and unescapes them, so that one is a question for the tree, while a leading
 * zero and an out-of-range integer are gone by then and have to be read from
 * the text. */
#ifndef RSP_STRICT_H
#define RSP_STRICT_H

#include <cjson/cJSON.h>

/* 0 if the text is framed and numbered as the grammar allows, else -1. */
int rsp_strict_text(const char *raw);

/* 0 if no object in the tree repeats a key, else -1. */
int rsp_strict_tree(const cJSON *value);

#endif
