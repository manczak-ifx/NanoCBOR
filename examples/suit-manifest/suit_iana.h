/*
 * SPDX-License-Identifier: CC0-1.0
 */

#ifndef SUIT_IANA_H
#define SUIT_IANA_H

/*
 * CBOR tags, SUIT_Envelope/SUIT_Manifest map keys and IANA-registered
 * COSE algorithm identifiers used by this example.
 *
 * Values come from draft-ietf-suit-manifest, as reflected in
 * docs/suit-manifest.cddl and docs/suit-manifest-extension.cddl.
 */

/* CBOR tags */
#define SUIT_CBOR_TAG_ENVELOPE 107U
#define SUIT_CBOR_TAG_MANIFEST 1070U

/* SUIT_Envelope map keys */
#define SUIT_ENVELOPE_KEY_AUTHENTICATION_WRAPPER 2U
#define SUIT_ENVELOPE_KEY_MANIFEST 3U

/* SUIT_Manifest map keys */
#define SUIT_MANIFEST_KEY_VERSION 1U
#define SUIT_MANIFEST_KEY_SEQUENCE_NUMBER 2U
#define SUIT_MANIFEST_KEY_COMMON 3U

#define SUIT_MANIFEST_VERSION_VALUE 1U

/* SUIT_Common map keys */
#define SUIT_COMMON_KEY_COMPONENTS 2U
#define SUIT_COMMON_KEY_SHARED_SEQUENCE 4U

/* SUIT_Condition identifiers (command sequence entries) */
#define SUIT_CONDITION_VENDOR_IDENTIFIER 1
#define SUIT_CONDITION_CLASS_IDENTIFIER 2
#define SUIT_CONDITION_VERSION 28

/* SUIT_Directive identifiers (command sequence entries) */
#define SUIT_DIRECTIVE_SET_COMPONENT_INDEX 12
#define SUIT_DIRECTIVE_OVERRIDE_PARAMETERS 20

/* $$SUIT_Parameters map keys */
#define SUIT_PARAMETER_VENDOR_IDENTIFIER 1
#define SUIT_PARAMETER_CLASS_IDENTIFIER 2
#define SUIT_PARAMETER_IMAGE_DIGEST 3
#define SUIT_PARAMETER_IMAGE_SIZE 14
#define SUIT_PARAMETER_CONTENT 18

/* IANA COSE algorithm identifiers (RFC 9053) relevant to SUIT digests */
#define SUIT_COSE_ALG_SHA_256 (-16)

#define SUIT_DIGEST_SHA256_BYTES 32U

/* RFC4122_UUID = bstr .size 16 */
#define SUIT_RFC4122_UUID_BYTES 16U

#endif
