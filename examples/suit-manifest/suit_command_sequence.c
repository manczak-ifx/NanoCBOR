/*
 * SPDX-License-Identifier: CC0-1.0
 */

#include "suit_command_sequence.h"

#include <inttypes.h>
#include <stdio.h>

#include "suit_iana.h"
#include "suit_parameters.h"
#include "suit_print.h"

static suit_decode_result_t _print_rep_policy_condition(const char *label,
                                                         nanocbor_value_t *it,
                                                         unsigned indent)
{
    uint64_t policy = 0;

    if (nanocbor_get_uint64(it, &policy) < NANOCBOR_OK) {
        if (nanocbor_skip(it) < NANOCBOR_OK) {
            fprintf(stderr,
                    "[suit-manifest] condition %s: unreadable argument, "
                    "aborting\n", label);
            return SUIT_DECODE_ERROR;
        }
        suit_print_indent(indent);
        printf("condition %s: unsupported argument form\n", label);
        return SUIT_DECODE_UNSUPPORTED;
    }
    suit_print_indent(indent);
    printf("condition %s: reporting=0x%" PRIx64 "\n", label, policy);
    return SUIT_DECODE_OK;
}

static suit_decode_result_t _print_set_component_index(nanocbor_value_t *it,
                                                        unsigned indent)
{
    uint64_t index = 0;

    /* only the plain uint form of IndexArg is supported */
    if (nanocbor_get_uint64(it, &index) >= NANOCBOR_OK) {
        suit_print_indent(indent);
        printf("directive set-component-index: %" PRIu64 "\n", index);
        return SUIT_DECODE_OK;
    }
    if (nanocbor_skip(it) < NANOCBOR_OK) {
        fprintf(stderr,
                "[suit-manifest] set-component-index: unreadable argument, "
                "aborting\n");
        return SUIT_DECODE_ERROR;
    }
    suit_print_indent(indent);
    printf("directive set-component-index: unsupported argument form\n");
    return SUIT_DECODE_UNSUPPORTED;
}

suit_decode_result_t suit_command_sequence_decode(nanocbor_value_t *it,
                                                  unsigned indent)
{
    nanocbor_value_t sequence;

    if (nanocbor_enter_array(it, &sequence) < NANOCBOR_OK) {
        fprintf(stderr, "[suit-manifest] command sequence is not a CBOR array\n");
        return SUIT_DECODE_ERROR;
    }

    while (!nanocbor_at_end(&sequence)) {
        int64_t command = 0;
        if (nanocbor_get_int64(&sequence, &command) < NANOCBOR_OK) {
            fprintf(stderr, "[suit-manifest] malformed command id\n");
            return SUIT_DECODE_ERROR;
        }

        suit_decode_result_t res;
        switch (command) {
        case SUIT_CONDITION_VENDOR_IDENTIFIER:
            res = _print_rep_policy_condition("vendor-identifier", &sequence,
                                              indent);
            break;
        case SUIT_CONDITION_CLASS_IDENTIFIER:
            res = _print_rep_policy_condition("class-identifier", &sequence,
                                              indent);
            break;
        case SUIT_CONDITION_VERSION:
            res = _print_rep_policy_condition("version", &sequence, indent);
            break;
        case SUIT_DIRECTIVE_SET_COMPONENT_INDEX:
            res = _print_set_component_index(&sequence, indent);
            break;
        case SUIT_DIRECTIVE_OVERRIDE_PARAMETERS:
            suit_print_indent(indent);
            printf("directive override-parameters:\n");
            res = suit_parameters_decode(&sequence, indent + 1);
            break;
        default:
            if (nanocbor_skip(&sequence) < NANOCBOR_OK) {
                fprintf(stderr,
                        "[suit-manifest] command %" PRId64
                        ": unreadable argument, aborting\n", command);
                return SUIT_DECODE_ERROR;
            }
            suit_print_unsupported("command", (uint64_t)command, indent);
            res = SUIT_DECODE_UNSUPPORTED;
            break;
        }
        if (res == SUIT_DECODE_ERROR) {
            return SUIT_DECODE_ERROR;
        }
    }

    if (nanocbor_leave_container(it, &sequence) < NANOCBOR_OK) {
        fprintf(stderr, "[suit-manifest] command sequence has trailing data\n");
        return SUIT_DECODE_ERROR;
    }
    return SUIT_DECODE_OK;
}
