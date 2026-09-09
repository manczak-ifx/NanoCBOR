/*
 * SPDX-License-Identifier: CC0-1.0
 */

#include "suit_parameters.h"

#include <inttypes.h>
#include <stdio.h>

#include "suit_digest.h"
#include "suit_iana.h"
#include "suit_print.h"

static suit_decode_result_t _print_uuid(const char *label,
                                        nanocbor_value_t *it, unsigned indent)
{
    const uint8_t *uuid = NULL;
    size_t uuid_len = 0;

    if (nanocbor_get_bstr(it, &uuid, &uuid_len) < NANOCBOR_OK) {
        /* not a plain byte string (e.g. tagged cbor-pen form): best effort skip */
        if (nanocbor_skip(it) < NANOCBOR_OK) {
            fprintf(stderr,
                    "[suit-manifest] %s: unreadable value, aborting\n", label);
            return SUIT_DECODE_ERROR;
        }
        suit_print_indent(indent);
        printf("%s: unsupported (not a plain byte string)\n", label);
        return SUIT_DECODE_UNSUPPORTED;
    }
    if (uuid_len != SUIT_RFC4122_UUID_BYTES) {
        suit_print_indent(indent);
        printf("%s: unsupported (expected a 16-byte UUID, got %zu bytes)\n",
               label, uuid_len);
        return SUIT_DECODE_UNSUPPORTED;
    }
    suit_print_indent(indent);
    printf("%s: ", label);
    suit_print_bytes(uuid, uuid_len);
    printf("\n");
    return SUIT_DECODE_OK;
}

static suit_decode_result_t _print_uint(const char *label,
                                        nanocbor_value_t *it, unsigned indent)
{
    uint64_t value = 0;

    if (nanocbor_get_uint64(it, &value) < NANOCBOR_OK) {
        if (nanocbor_skip(it) < NANOCBOR_OK) {
            fprintf(stderr,
                    "[suit-manifest] %s: unreadable value, aborting\n", label);
            return SUIT_DECODE_ERROR;
        }
        suit_print_indent(indent);
        printf("%s: unsupported (not a plain uint)\n", label);
        return SUIT_DECODE_UNSUPPORTED;
    }
    suit_print_indent(indent);
    printf("%s: %" PRIu64 "\n", label, value);
    return SUIT_DECODE_OK;
}

static suit_decode_result_t _print_content(nanocbor_value_t *it,
                                           unsigned indent)
{
    const uint8_t *content = NULL;
    size_t content_len = 0;

    if (nanocbor_get_bstr(it, &content, &content_len) < NANOCBOR_OK) {
        if (nanocbor_skip(it) < NANOCBOR_OK) {
            fprintf(stderr,
                    "[suit-manifest] content: unreadable value, aborting\n");
            return SUIT_DECODE_ERROR;
        }
        suit_print_indent(indent);
        printf("content: unsupported (not a plain byte string)\n");
        return SUIT_DECODE_UNSUPPORTED;
    }
    suit_print_indent(indent);
    printf("content: ");
    suit_print_bytes(content, content_len);
    printf("\n");
    return SUIT_DECODE_OK;
}

static suit_decode_result_t _print_image_digest(nanocbor_value_t *it,
                                                unsigned indent)
{
    const uint8_t *encoded = NULL;
    size_t encoded_len = 0;
    suit_digest_t digest;

    if (nanocbor_get_bstr(it, &encoded, &encoded_len) < NANOCBOR_OK) {
        if (nanocbor_skip(it) < NANOCBOR_OK) {
            fprintf(stderr,
                    "[suit-manifest] image-digest: unreadable value, aborting\n");
            return SUIT_DECODE_ERROR;
        }
        suit_print_indent(indent);
        printf("image-digest: unsupported (not a plain byte string)\n");
        return SUIT_DECODE_UNSUPPORTED;
    }

    suit_decode_result_t res = suit_digest_decode(encoded, encoded_len,
                                                  &digest);
    suit_print_indent(indent);
    if (res != SUIT_DECODE_OK) {
        printf("image-digest: unsupported (algorithm %" PRId64 ")\n",
               digest.algorithm);
        return SUIT_DECODE_UNSUPPORTED;
    }
    printf("image-digest: algorithm=sha256 digest=");
    suit_print_bytes(digest.bytes, digest.len);
    printf("\n");
    return SUIT_DECODE_OK;
}

suit_decode_result_t suit_parameters_decode(nanocbor_value_t *it,
                                            unsigned indent)
{
    nanocbor_value_t params;

    if (nanocbor_enter_map(it, &params) < NANOCBOR_OK) {
        fprintf(stderr, "[suit-manifest] parameters is not a CBOR map\n");
        return SUIT_DECODE_ERROR;
    }

    while (!nanocbor_at_end(&params)) {
        int64_t key = 0;
        if (nanocbor_get_int64(&params, &key) < NANOCBOR_OK) {
            fprintf(stderr, "[suit-manifest] malformed parameter key\n");
            return SUIT_DECODE_ERROR;
        }

        suit_decode_result_t res;
        switch (key) {
        case SUIT_PARAMETER_VENDOR_IDENTIFIER:
            res = _print_uuid("vendor-id", &params, indent);
            break;
        case SUIT_PARAMETER_CLASS_IDENTIFIER:
            res = _print_uuid("class-id", &params, indent);
            break;
        case SUIT_PARAMETER_IMAGE_SIZE:
            res = _print_uint("image-size", &params, indent);
            break;
        case SUIT_PARAMETER_CONTENT:
            res = _print_content(&params, indent);
            break;
        case SUIT_PARAMETER_IMAGE_DIGEST:
            res = _print_image_digest(&params, indent);
            break;
        default:
            if (nanocbor_skip(&params) < NANOCBOR_OK) {
                fprintf(stderr,
                        "[suit-manifest] parameter %" PRId64
                        ": unreadable value, aborting\n", key);
                return SUIT_DECODE_ERROR;
            }
            suit_print_unsupported("parameter", (uint64_t)key, indent);
            res = SUIT_DECODE_UNSUPPORTED;
            break;
        }
        if (res == SUIT_DECODE_ERROR) {
            return SUIT_DECODE_ERROR;
        }
    }

    if (nanocbor_leave_container(it, &params) < NANOCBOR_OK) {
        fprintf(stderr, "[suit-manifest] parameters map has trailing data\n");
        return SUIT_DECODE_ERROR;
    }
    return SUIT_DECODE_OK;
}
