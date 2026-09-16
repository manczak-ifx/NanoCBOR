/*
 * SPDX-License-Identifier: CC0-1.0
 */

#ifndef SUIT_MANIFEST_AUTH_H
#define SUIT_MANIFEST_AUTH_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef enum {
    SUIT_AUTH_OK = 0,
    SUIT_AUTH_INVALID_INPUT = -1,
    SUIT_AUTH_UNSUPPORTED = -2,
    SUIT_AUTH_DIGEST_MISMATCH = -3,
    SUIT_AUTH_CRYPTO_ERROR = -4,
    SUIT_AUTH_SIGNATURE_MISMATCH = -5,
} suit_auth_result_t;

/*
 * Authenticates the SUIT envelope in `input`, always verifying the
 * mandatory manifest digest. If `check_signature` is true, every
 * COSE_Sign1 authentication block present is additionally verified
 * against `signature_key_path` (a PEM-encoded EC public key file);
 * `signature_key_path` is unused otherwise. On success, `*manifest`
 * and `*manifest_len` point at the verified manifest content.
 */
suit_auth_result_t suit_manifest_authenticate(const uint8_t *input,
                                              size_t input_len,
                                              bool check_signature,
                                              const char *signature_key_path,
                                              const uint8_t **manifest,
                                              size_t *manifest_len);

#endif
