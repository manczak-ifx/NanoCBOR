/*
 * SPDX-License-Identifier: CC0-1.0
 */

#include "auth.h"

#include <inttypes.h>
#include <openssl/evp.h>
#include <stdio.h>

#include "nanocbor/nanocbor.h"
#include "suit_digest.h"
#include "suit_iana.h"

static void _print_digest(const char *label, const uint8_t *digest,
                          size_t digest_len)
{
    fprintf(stderr, "[suit-auth] %s: ", label);
    for (size_t i = 0; i < digest_len; i++) {
        fprintf(stderr, "%02x", digest[i]);
    }
    fprintf(stderr, "\n");
}

static int _constant_time_equal(const uint8_t *left, const uint8_t *right,
                                size_t length)
{
    uint8_t difference = 0;
    for (size_t i = 0; i < length; i++) {
        difference |= left[i] ^ right[i];
    }
    return difference == 0;
}

static suit_auth_result_t _sha256(const uint8_t *data, size_t data_len,
                                  uint8_t digest[SUIT_DIGEST_SHA256_BYTES])
{
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    unsigned int digest_len = 0;
    int result = 0;

    if (!context) {
        return SUIT_AUTH_CRYPTO_ERROR;
    }

    result = EVP_DigestInit_ex(context, EVP_sha256(), NULL);
    result = result && EVP_DigestUpdate(context, data, data_len);
    result = result && EVP_DigestFinal_ex(context, digest, &digest_len);
    EVP_MD_CTX_free(context);

    if (!result || digest_len != SUIT_DIGEST_SHA256_BYTES) {
        return SUIT_AUTH_CRYPTO_ERROR;
    }
    return SUIT_AUTH_OK;
}

static suit_auth_result_t _verify_digest(const uint8_t *authentication,
                                         size_t authentication_len,
                                         const uint8_t *manifest,
                                         size_t manifest_len)
{
    nanocbor_value_t authentication_value;
    nanocbor_value_t authentication_array;
    const uint8_t *digest_encoded = NULL;
    size_t digest_encoded_len = 0;
    suit_digest_t digest;

    _print_digest("manifest field input (bstr header + content)", manifest,
                  manifest_len);
    nanocbor_decoder_init(&authentication_value, authentication,
                          authentication_len);
    fprintf(stderr, "[suit-auth] decoding authentication wrapper (%zu bytes)\n",
            authentication_len);
    if (nanocbor_enter_array(&authentication_value, &authentication_array)
        < NANOCBOR_OK) {
        fprintf(stderr, "[suit-auth] authentication wrapper is not an array\n");
        return SUIT_AUTH_INVALID_INPUT;
    }
    if (nanocbor_get_bstr(&authentication_array, &digest_encoded,
                          &digest_encoded_len)
        < NANOCBOR_OK) {
        fprintf(stderr, "[suit-auth] missing authentication digest\n");
        return SUIT_AUTH_INVALID_INPUT;
    }

    fprintf(stderr, "[suit-auth] decoding digest structure (%zu bytes)\n",
            digest_encoded_len);
    if (suit_digest_decode(digest_encoded, digest_encoded_len, &digest)
        != SUIT_DECODE_OK) {
        fprintf(stderr, "[suit-auth] unsupported digest structure\n");
        return SUIT_AUTH_UNSUPPORTED;
    }
    fprintf(stderr, "[suit-auth] digest algorithm: %" PRId64 "\n",
            digest.algorithm);
    _print_digest("expected digest", digest.bytes, digest.len);

    while (!nanocbor_at_end(&authentication_array)) {
        const uint8_t *authentication_block = NULL;
        size_t authentication_block_len = 0;
        if (nanocbor_get_bstr(&authentication_array, &authentication_block,
                              &authentication_block_len)
            < NANOCBOR_OK) {
            fprintf(stderr, "[suit-auth] malformed authentication block\n");
            return SUIT_AUTH_INVALID_INPUT;
        }
        fprintf(stderr,
                "[suit-auth] unsupported authentication block (%zu bytes)\n",
                authentication_block_len);
        return SUIT_AUTH_UNSUPPORTED;
    }

    fprintf(stderr,
            "[suit-auth] hashing manifest field, header included (%zu bytes)\n",
            manifest_len);
    uint8_t calculated_digest[SUIT_DIGEST_SHA256_BYTES];

    suit_auth_result_t result = _sha256(manifest, manifest_len,
                                        calculated_digest);
    if (result != SUIT_AUTH_OK) {
        fprintf(stderr, "[suit-auth] SHA-256 calculation failed\n");
        return result;
    }
    _print_digest("calculated digest", calculated_digest,
                  sizeof(calculated_digest));
    if (!_constant_time_equal(calculated_digest, digest.bytes,
                              SUIT_DIGEST_SHA256_BYTES)) {
        fprintf(stderr, "[suit-auth] digest mismatch\n");
        return SUIT_AUTH_DIGEST_MISMATCH;
    }
    fprintf(stderr, "[suit-auth] digest verified\n");
    return SUIT_AUTH_OK;
}

suit_auth_result_t suit_manifest_authenticate(const uint8_t *input,
                                              size_t input_len,
                                              const uint8_t **verified_manifest,
                                              size_t *verified_manifest_len)
{
    nanocbor_value_t envelope;
    nanocbor_value_t envelope_map;
    const uint8_t *authentication = NULL;
    const uint8_t *manifest = NULL;
    const uint8_t *manifest_encoded = NULL;
    size_t authentication_len = 0;
    size_t manifest_len = 0;
    size_t manifest_encoded_len = 0;
    bool has_authentication = false;
    bool has_manifest = false;

    if (!input || input_len == 0 || !verified_manifest || !verified_manifest_len) {
        fprintf(stderr, "[suit-auth] invalid input arguments\n");
        return SUIT_AUTH_INVALID_INPUT;
    }

    *verified_manifest = NULL;
    *verified_manifest_len = 0;

    nanocbor_decoder_init(&envelope, input, input_len);
    uint32_t tag = 0;
    if (nanocbor_get_tag(&envelope, &tag) < NANOCBOR_OK
        || tag != SUIT_CBOR_TAG_ENVELOPE
        || nanocbor_enter_map(&envelope, &envelope_map) < NANOCBOR_OK) {
        fprintf(stderr, "[suit-auth] expected tagged SUIT envelope (tag 107)\n");
        return SUIT_AUTH_UNSUPPORTED;
    }
    fprintf(stderr, "[suit-auth] found SUIT envelope tag: %" PRIu32 "\n", tag);

    while (!nanocbor_at_end(&envelope_map)) {
        uint64_t key = 0;
        if (nanocbor_get_uint64(&envelope_map, &key) < NANOCBOR_OK) {
            fprintf(stderr, "[suit-auth] malformed envelope key\n");
            return SUIT_AUTH_INVALID_INPUT;
        }
        if (key == SUIT_ENVELOPE_KEY_AUTHENTICATION_WRAPPER) {
            if (nanocbor_get_bstr(&envelope_map, &authentication,
                                  &authentication_len)
                < NANOCBOR_OK) {
                fprintf(stderr, "[suit-auth] malformed authentication field\n");
                return SUIT_AUTH_INVALID_INPUT;
            }
            has_authentication = true;
            fprintf(stderr, "[suit-auth] found authentication field (%zu bytes)\n",
                    authentication_len);
        }
        else if (key == SUIT_ENVELOPE_KEY_MANIFEST) {
            /* keep the field start to hash the bstr header alongside its content */
            const uint8_t *field_start = envelope_map.cur;
            if (nanocbor_get_bstr(&envelope_map, &manifest, &manifest_len)
                < NANOCBOR_OK) {
                fprintf(stderr, "[suit-auth] malformed manifest field\n");
                return SUIT_AUTH_INVALID_INPUT;
            }
            manifest_encoded = field_start;
            manifest_encoded_len = (size_t)(envelope_map.cur - field_start);
            has_manifest = true;
            fprintf(stderr,
                    "[suit-auth] found manifest field (%zu bytes encoded, "
                    "%zu bytes content)\n",
                    manifest_encoded_len, manifest_len);
        }
        else if (nanocbor_skip(&envelope_map) < NANOCBOR_OK) {
            fprintf(stderr, "[suit-auth] malformed envelope value\n");
            return SUIT_AUTH_INVALID_INPUT;
        }
    }

    if (!has_authentication || !has_manifest) {
        fprintf(stderr, "[suit-auth] required envelope fields are missing\n");
        return SUIT_AUTH_INVALID_INPUT;
    }
    /* digest covers the full bstr encoding of suit-manifest, header included */
    suit_auth_result_t result = _verify_digest(
        authentication, authentication_len, manifest_encoded,
        manifest_encoded_len);
    if (result == SUIT_AUTH_OK) {
        *verified_manifest = manifest;
        *verified_manifest_len = manifest_len;
        fprintf(stderr, "[suit-auth] manifest accepted\n");
    }
    return result;
}
