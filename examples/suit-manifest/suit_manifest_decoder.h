/*
 * SPDX-License-Identifier: CC0-1.0
 */

#ifndef SUIT_MANIFEST_DECODER_H
#define SUIT_MANIFEST_DECODER_H

#include <stddef.h>
#include <stdint.h>

#include "suit_types.h"

/*
 * Decodes and prints the supported members of a SUIT_Manifest:
 * suit-manifest-version, suit-manifest-sequence-number and
 * suit-common. Any other manifest member is reported as unsupported.
 * `manifest`/`manifest_len` are the already digest-verified content
 * of the suit-manifest bstr.
 */
suit_decode_result_t suit_manifest_decode(const uint8_t *manifest,
                                          size_t manifest_len);

#endif
