/*
 * SPDX-License-Identifier: CC0-1.0
 */

#include "suit_manifest_decoder.h"

#include <inttypes.h>
#include <stdio.h>

#include "nanocbor/nanocbor.h"
#include "suit_common.h"
#include "suit_iana.h"
#include "suit_print.h"

static suit_decode_result_t _print_version(nanocbor_value_t *it)
{
    uint64_t version = 0;

    if (nanocbor_get_uint64(it, &version) < NANOCBOR_OK) {
        fprintf(stderr, "[suit-manifest] version: unreadable value\n");
        return SUIT_DECODE_ERROR;
    }
    printf("version: %" PRIu64 "%s\n", version,
           version == SUIT_MANIFEST_VERSION_VALUE ? "" : " (unexpected)");
    return SUIT_DECODE_OK;
}

static suit_decode_result_t _print_sequence_number(nanocbor_value_t *it)
{
    uint64_t sequence = 0;

    if (nanocbor_get_uint64(it, &sequence) < NANOCBOR_OK) {
        fprintf(stderr, "[suit-manifest] sequence-number: unreadable value\n");
        return SUIT_DECODE_ERROR;
    }
    printf("sequence-number: %" PRIu64 "\n", sequence);
    return SUIT_DECODE_OK;
}

static suit_decode_result_t _print_common(nanocbor_value_t *it)
{
    const uint8_t *encoded = NULL;
    size_t encoded_len = 0;

    if (nanocbor_get_bstr(it, &encoded, &encoded_len) < NANOCBOR_OK) {
        fprintf(stderr, "[suit-manifest] common: not a byte string\n");
        return SUIT_DECODE_ERROR;
    }
    printf("common:\n");
    return suit_common_decode(encoded, encoded_len, 1);
}

suit_decode_result_t suit_manifest_decode(const uint8_t *manifest,
                                          size_t manifest_len)
{
    nanocbor_value_t manifest_cbor;
    nanocbor_value_t manifest_map;

    nanocbor_decoder_init(&manifest_cbor, manifest, manifest_len);
    if (nanocbor_enter_map(&manifest_cbor, &manifest_map) < NANOCBOR_OK) {
        fprintf(stderr, "[suit-manifest] manifest is not a CBOR map\n");
        return SUIT_DECODE_ERROR;
    }

    while (!nanocbor_at_end(&manifest_map)) {
        uint64_t key = 0;
        if (nanocbor_get_uint64(&manifest_map, &key) < NANOCBOR_OK) {
            fprintf(stderr, "[suit-manifest] malformed manifest key\n");
            return SUIT_DECODE_ERROR;
        }

        suit_decode_result_t res;
        switch (key) {
        case SUIT_MANIFEST_KEY_VERSION:
            res = _print_version(&manifest_map);
            break;
        case SUIT_MANIFEST_KEY_SEQUENCE_NUMBER:
            res = _print_sequence_number(&manifest_map);
            break;
        case SUIT_MANIFEST_KEY_COMMON:
            res = _print_common(&manifest_map);
            break;
        default:
            if (nanocbor_skip(&manifest_map) < NANOCBOR_OK) {
                fprintf(stderr, "[suit-manifest] malformed manifest member\n");
                return SUIT_DECODE_ERROR;
            }
            suit_print_unsupported("manifest member", key, 0);
            res = SUIT_DECODE_UNSUPPORTED;
            break;
        }
        if (res == SUIT_DECODE_ERROR) {
            return SUIT_DECODE_ERROR;
        }
    }

    if (nanocbor_leave_container(&manifest_cbor, &manifest_map)
        < NANOCBOR_OK) {
        fprintf(stderr, "[suit-manifest] manifest has trailing data\n");
        return SUIT_DECODE_ERROR;
    }
    return SUIT_DECODE_OK;
}
