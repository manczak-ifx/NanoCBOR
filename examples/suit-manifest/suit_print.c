/*
 * SPDX-License-Identifier: CC0-1.0
 */

#include "suit_print.h"

#include <inttypes.h>
#include <stdio.h>

static bool _pretty = false;

void suit_print_set_pretty(bool pretty)
{
    _pretty = pretty;
}

void suit_print_indent(unsigned indent)
{
    if (!_pretty) {
        return;
    }
    for (unsigned i = 0; i < indent; i++) {
        printf("  ");
    }
}

void suit_print_unsupported(const char *kind, uint64_t id, unsigned indent)
{
    suit_print_indent(indent);
    printf("%s %" PRIu64 ": unsupported\n", kind, id);
}

void suit_print_bytes(const uint8_t *data, size_t len)
{
    printf("h'");
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("'");
}
