/*
 * SPDX-License-Identifier: CC0-1.0
 */

#ifndef SUIT_COMMAND_SEQUENCE_H
#define SUIT_COMMAND_SEQUENCE_H

#include "nanocbor/nanocbor.h"
#include "suit_types.h"

/*
 * Decodes and prints a SUIT_Command_Sequence / SUIT_Shared_Sequence
 * array of (command-id, argument) pairs. `it` must be positioned at
 * the array itself (not bstr-wrapped). Unsupported commands are
 * skipped and reported, decoding continues for the remaining entries.
 */
suit_decode_result_t suit_command_sequence_decode(nanocbor_value_t *it,
                                                  unsigned indent);

#endif
