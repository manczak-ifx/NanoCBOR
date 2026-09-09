/*
 * SPDX-License-Identifier: CC0-1.0
 */

#ifndef SUIT_PARAMETERS_H
#define SUIT_PARAMETERS_H

#include "nanocbor/nanocbor.h"
#include "suit_types.h"

/*
 * Decodes and prints a {+ $$SUIT_Parameters} map, the argument of
 * suit-directive-override-parameters. `it` must be positioned at the
 * map itself (not bstr-wrapped). Unsupported parameter identifiers are
 * skipped and reported, decoding continues for the remaining entries.
 */
suit_decode_result_t suit_parameters_decode(nanocbor_value_t *it,
                                            unsigned indent);

#endif
