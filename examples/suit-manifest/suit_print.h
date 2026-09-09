/*
 * SPDX-License-Identifier: CC0-1.0
 */

#ifndef SUIT_PRINT_H
#define SUIT_PRINT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Controls whether suit_print_indent() emits indentation whitespace. */
void suit_print_set_pretty(bool pretty);

void suit_print_indent(unsigned indent);

/* Prints "<kind> <id>: unsupported\n", indented. */
void suit_print_unsupported(const char *kind, uint64_t id, unsigned indent);

/* Prints `data` as a CBOR-style h'...' hex byte string, no trailing newline. */
void suit_print_bytes(const uint8_t *data, size_t len);

#endif
