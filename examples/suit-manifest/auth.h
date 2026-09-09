/*
 * SPDX-License-Identifier: CC0-1.0
 */

#ifndef SUIT_MANIFEST_AUTH_H
#define SUIT_MANIFEST_AUTH_H

#include <stddef.h>
#include <stdint.h>

typedef enum {
    SUIT_AUTH_OK = 0,
    SUIT_AUTH_INVALID_INPUT = -1,
    SUIT_AUTH_UNSUPPORTED = -2,
    SUIT_AUTH_DIGEST_MISMATCH = -3,
    SUIT_AUTH_CRYPTO_ERROR = -4,
} suit_auth_result_t;

suit_auth_result_t suit_manifest_authenticate(const uint8_t *input,
                                              size_t input_len,
                                              const uint8_t **manifest,
                                              size_t *manifest_len);

#endif
