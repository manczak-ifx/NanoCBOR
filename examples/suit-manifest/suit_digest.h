/*
 * SPDX-License-Identifier: CC0-1.0
 */

#ifndef SUIT_DIGEST_H
#define SUIT_DIGEST_H

#include <stddef.h>
#include <stdint.h>

#include "suit_types.h"

/* Decoded SUIT_Digest = [suit-digest-algorithm-id, suit-digest-bytes]. */
typedef struct {
    int64_t algorithm;
    const uint8_t *bytes;
    size_t len;
} suit_digest_t;

/*
 * Decodes a SUIT_Digest from `encoded` (the content of its enclosing
 * bstr). Only cose-alg-sha-256 with a 32-byte digest is supported;
 * any other algorithm or length yields SUIT_DECODE_UNSUPPORTED, with
 * `out->algorithm` still populated for diagnostics.
 */
suit_decode_result_t suit_digest_decode(const uint8_t *encoded,
                                        size_t encoded_len,
                                        suit_digest_t *out);

#endif
