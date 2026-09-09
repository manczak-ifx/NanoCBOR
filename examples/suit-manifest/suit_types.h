/*
 * SPDX-License-Identifier: CC0-1.0
 */

#ifndef SUIT_TYPES_H
#define SUIT_TYPES_H

/*
 * Shared result type for the SUIT manifest decoding modules.
 *
 * Decoding functions always consume the CBOR item they were given,
 * whether or not it is one of the supported members, so that callers
 * can keep iterating a sequence or map after an unsupported member.
 * Only SUIT_DECODE_ERROR means the cursor position is no longer
 * reliable and decoding must stop.
 */
typedef enum {
    SUIT_DECODE_OK = 0,          /**< item decoded and printed */
    SUIT_DECODE_UNSUPPORTED = 1, /**< item not supported, but skipped cleanly */
    SUIT_DECODE_ERROR = -1,      /**< malformed CBOR, cannot continue */
} suit_decode_result_t;

#endif
