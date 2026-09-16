/*
 * SPDX-License-Identifier: CC0-1.0
 */

#ifndef SUIT_SIGNATURE_H
#define SUIT_SIGNATURE_H

#include <stddef.h>
#include <stdint.h>

#include "auth.h"

/*
 * Verifies one SUIT authentication block against the digest it is
 * expected to cover.
 *
 * `block`/`block_len` is the content of the bstr authentication-block
 * entry: a COSE_Sign1 structure, optionally wrapped in CBOR tag 18.
 * `digest_encoded`/`digest_encoded_len` is the SUIT_Digest structure's
 * own CBOR encoding (no enclosing bstr header), i.e. the same bytes
 * passed to suit_digest_decode(). The COSE_Sign1 payload may be
 * detached (nil), in which case `digest_encoded` is used as the signed
 * content, or embedded directly, in which case it must byte-match
 * `digest_encoded`. `key_path` names a PEM-encoded EC public key file.
 *
 * Only COSE algorithm ES256 (ECDSA P-256 with SHA-256) is supported;
 * anything else yields SUIT_AUTH_UNSUPPORTED.
 */
suit_auth_result_t suit_signature_verify(const uint8_t *block, size_t block_len,
                                         const uint8_t *digest_encoded,
                                         size_t digest_encoded_len,
                                         const char *key_path);

#endif
