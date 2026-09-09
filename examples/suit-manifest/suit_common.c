/*
 * SPDX-License-Identifier: CC0-1.0
 */

#include "suit_common.h"

#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>

#include "nanocbor/nanocbor.h"
#include "suit_command_sequence.h"
#include "suit_iana.h"
#include "suit_print.h"

static suit_decode_result_t _print_component_identifier(
    nanocbor_value_t *it, unsigned indent)
{
    nanocbor_value_t identifier;
    bool first = true;

    if (nanocbor_enter_array(it, &identifier) < NANOCBOR_OK) {
        fprintf(stderr, "[suit-manifest] component identifier is not an array\n");
        return SUIT_DECODE_ERROR;
    }

    suit_print_indent(indent);
    printf("- ");
    while (!nanocbor_at_end(&identifier)) {
        const uint8_t *part = NULL;
        size_t part_len = 0;
        if (nanocbor_get_bstr(&identifier, &part, &part_len) < NANOCBOR_OK) {
            fprintf(stderr,
                    "[suit-manifest] component identifier part is not a "
                    "byte string\n");
            return SUIT_DECODE_ERROR;
        }
        if (!first) {
            printf(" / ");
        }
        suit_print_bytes(part, part_len);
        first = false;
    }
    printf("\n");

    if (nanocbor_leave_container(it, &identifier) < NANOCBOR_OK) {
        fprintf(stderr,
                "[suit-manifest] component identifier has trailing data\n");
        return SUIT_DECODE_ERROR;
    }
    return SUIT_DECODE_OK;
}

static suit_decode_result_t _print_components(nanocbor_value_t *it,
                                              unsigned indent)
{
    nanocbor_value_t components;

    if (nanocbor_enter_array(it, &components) < NANOCBOR_OK) {
        fprintf(stderr, "[suit-manifest] components is not an array\n");
        return SUIT_DECODE_ERROR;
    }

    suit_print_indent(indent);
    printf("components:\n");

    while (!nanocbor_at_end(&components)) {
        suit_decode_result_t res
            = _print_component_identifier(&components, indent + 1);
        if (res == SUIT_DECODE_ERROR) {
            return SUIT_DECODE_ERROR;
        }
    }

    if (nanocbor_leave_container(it, &components) < NANOCBOR_OK) {
        fprintf(stderr, "[suit-manifest] components array has trailing data\n");
        return SUIT_DECODE_ERROR;
    }
    return SUIT_DECODE_OK;
}

static suit_decode_result_t _print_shared_sequence(nanocbor_value_t *it,
                                                   unsigned indent)
{
    const uint8_t *encoded = NULL;
    size_t encoded_len = 0;
    nanocbor_value_t sequence_cbor;

    if (nanocbor_get_bstr(it, &encoded, &encoded_len) < NANOCBOR_OK) {
        fprintf(stderr,
                "[suit-manifest] shared-sequence is not a byte string\n");
        return SUIT_DECODE_ERROR;
    }

    suit_print_indent(indent);
    printf("shared-sequence:\n");

    nanocbor_decoder_init(&sequence_cbor, encoded, encoded_len);
    return suit_command_sequence_decode(&sequence_cbor, indent + 1);
}

suit_decode_result_t suit_common_decode(const uint8_t *encoded,
                                        size_t encoded_len, unsigned indent)
{
    nanocbor_value_t common_cbor;
    nanocbor_value_t common_map;

    nanocbor_decoder_init(&common_cbor, encoded, encoded_len);
    if (nanocbor_enter_map(&common_cbor, &common_map) < NANOCBOR_OK) {
        fprintf(stderr, "[suit-manifest] common is not a CBOR map\n");
        return SUIT_DECODE_ERROR;
    }

    while (!nanocbor_at_end(&common_map)) {
        int64_t key = 0;
        if (nanocbor_get_int64(&common_map, &key) < NANOCBOR_OK) {
            fprintf(stderr, "[suit-manifest] malformed common key\n");
            return SUIT_DECODE_ERROR;
        }

        suit_decode_result_t res;
        switch (key) {
        case SUIT_COMMON_KEY_COMPONENTS:
            res = _print_components(&common_map, indent);
            break;
        case SUIT_COMMON_KEY_SHARED_SEQUENCE:
            res = _print_shared_sequence(&common_map, indent);
            break;
        default:
            if (nanocbor_skip(&common_map) < NANOCBOR_OK) {
                fprintf(stderr,
                        "[suit-manifest] common member %" PRId64
                        ": unreadable value, aborting\n", key);
                return SUIT_DECODE_ERROR;
            }
            suit_print_unsupported("common member", (uint64_t)key, indent);
            res = SUIT_DECODE_UNSUPPORTED;
            break;
        }
        if (res == SUIT_DECODE_ERROR) {
            return SUIT_DECODE_ERROR;
        }
    }

    if (nanocbor_leave_container(&common_cbor, &common_map) < NANOCBOR_OK) {
        fprintf(stderr, "[suit-manifest] common map has trailing data\n");
        return SUIT_DECODE_ERROR;
    }
    return SUIT_DECODE_OK;
}
