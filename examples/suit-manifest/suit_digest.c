/*
 * SPDX-License-Identifier: CC0-1.0
 */

#include "suit_digest.h"

#include <stdio.h>

#include "nanocbor/nanocbor.h"
#include "suit_iana.h"

suit_decode_result_t suit_digest_decode(const uint8_t *encoded,
                                        size_t encoded_len,
                                        suit_digest_t *out)
{
    nanocbor_value_t digest_cbor;
    nanocbor_value_t digest_array;

    out->algorithm = 0;
    out->bytes = NULL;
    out->len = 0;

    nanocbor_decoder_init(&digest_cbor, encoded, encoded_len);
    if (nanocbor_enter_array(&digest_cbor, &digest_array) < NANOCBOR_OK) {
        fprintf(stderr, "[suit-manifest] digest is not a CBOR array\n");
        return SUIT_DECODE_ERROR;
    }
    if (nanocbor_get_int64(&digest_array, &out->algorithm) < NANOCBOR_OK) {
        fprintf(stderr, "[suit-manifest] digest algorithm is not an int\n");
        return SUIT_DECODE_ERROR;
    }
    if (nanocbor_get_bstr(&digest_array, &out->bytes, &out->len)
        < NANOCBOR_OK) {
        fprintf(stderr, "[suit-manifest] digest bytes are not a byte string\n");
        return SUIT_DECODE_ERROR;
    }

    if (out->algorithm != SUIT_COSE_ALG_SHA_256
        || out->len != SUIT_DIGEST_SHA256_BYTES) {
        return SUIT_DECODE_UNSUPPORTED;
    }
    return SUIT_DECODE_OK;
}
