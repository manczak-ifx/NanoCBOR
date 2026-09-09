/*
 * SPDX-License-Identifier: CC0-1.0
 */

#ifndef SUIT_COMMON_H
#define SUIT_COMMON_H

#include <stddef.h>
#include <stdint.h>

#include "suit_types.h"

/*
 * Decodes and prints the content of a SUIT_Common bstr
 * (suit-common => bstr .cbor SUIT_Common). `encoded`/`encoded_len`
 * are the bstr content, without its own CBOR header.
 */
suit_decode_result_t suit_common_decode(const uint8_t *encoded,
                                        size_t encoded_len, unsigned indent);

#endif
