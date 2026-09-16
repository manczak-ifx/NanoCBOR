/*
 * SPDX-License-Identifier: CC0-1.0
 */

#include "suit_signature.h"

#include <inttypes.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <stdio.h>

#include "nanocbor/nanocbor.h"
#include "suit_iana.h"

/* "Signature1" tstr + array/bstr headers + protected header + digest bstr
 * comfortably fit well within this bound for ES256. */
#define SUIT_SIG_STRUCTURE_MAX_BYTES 256U
/* DER SEQUENCE of two 32-byte INTEGERs, plus ASN.1 overhead. */
#define SUIT_ECDSA_P256_DER_SIGNATURE_MAX_BYTES 72U

static EVP_PKEY *_load_public_key(const char *key_path)
{
    FILE *fp = fopen(key_path, "re");
    if (!fp) {
        fprintf(stderr, "[suit-sig] unable to open public key file: %s\n",
                key_path);
        return NULL;
    }
    EVP_PKEY *key = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!key) {
        fprintf(stderr, "[suit-sig] unable to parse PEM public key: %s\n",
                key_path);
    }
    return key;
}

/* COSE carries ECDSA signatures as raw r||s; OpenSSL's EVP verify path
 * expects the DER SEQUENCE{r,s} encoding instead. */
static int _der_from_raw_ecdsa_signature(const uint8_t *raw, size_t raw_len,
                                         uint8_t *der, size_t der_cap,
                                         size_t *der_len)
{
    if (raw_len != SUIT_ECDSA_P256_SIGNATURE_BYTES) {
        return -1;
    }
    size_t half = raw_len / 2;

    ECDSA_SIG *sig = ECDSA_SIG_new();
    if (!sig) {
        return -1;
    }
    BIGNUM *r = BN_bin2bn(raw, (int)half, NULL);
    BIGNUM *s = BN_bin2bn(raw + half, (int)half, NULL);
    if (!r || !s) {
        BN_free(r);
        BN_free(s);
        ECDSA_SIG_free(sig);
        return -1;
    }
    if (!ECDSA_SIG_set0(sig, r, s)) {
        /* ownership of r/s was not transferred on failure */
        BN_free(r);
        BN_free(s);
        ECDSA_SIG_free(sig);
        return -1;
    }

    int len = i2d_ECDSA_SIG(sig, NULL);
    if (len <= 0 || (size_t)len > der_cap) {
        ECDSA_SIG_free(sig);
        return -1;
    }
    uint8_t *cur = der;
    len = i2d_ECDSA_SIG(sig, &cur);
    ECDSA_SIG_free(sig);
    if (len <= 0) {
        return -1;
    }
    *der_len = (size_t)len;
    return 0;
}

static suit_auth_result_t _verify_es256(EVP_PKEY *key, const uint8_t *message,
                                        size_t message_len,
                                        const uint8_t *raw_signature,
                                        size_t raw_signature_len)
{
    uint8_t der_signature[SUIT_ECDSA_P256_DER_SIGNATURE_MAX_BYTES];
    size_t der_signature_len = 0;

    if (_der_from_raw_ecdsa_signature(raw_signature, raw_signature_len,
                                      der_signature, sizeof(der_signature),
                                      &der_signature_len)
        != 0) {
        fprintf(stderr, "[suit-sig] malformed ECDSA signature (%zu bytes)\n",
                raw_signature_len);
        return SUIT_AUTH_INVALID_INPUT;
    }

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        return SUIT_AUTH_CRYPTO_ERROR;
    }

    suit_auth_result_t result = SUIT_AUTH_CRYPTO_ERROR;
    if (EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, key) == 1) {
        int verified = EVP_DigestVerify(ctx, der_signature, der_signature_len,
                                        message, message_len);
        result = (verified == 1) ? SUIT_AUTH_OK : SUIT_AUTH_SIGNATURE_MISMATCH;
    }
    EVP_MD_CTX_free(ctx);
    return result;
}

/* protected header = { 1: cose-algorithm-id, ... } */
static suit_auth_result_t _protected_header_algorithm(const uint8_t *protected_header,
                                                       size_t protected_header_len,
                                                       int64_t *algorithm)
{
    nanocbor_value_t header_value;
    nanocbor_value_t header_map;
    bool found = false;

    nanocbor_decoder_init(&header_value, protected_header, protected_header_len);
    if (nanocbor_enter_map(&header_value, &header_map) < NANOCBOR_OK) {
        fprintf(stderr, "[suit-sig] protected header is not a map\n");
        return SUIT_AUTH_INVALID_INPUT;
    }

    while (!nanocbor_at_end(&header_map)) {
        int64_t key = 0;
        if (nanocbor_get_int64(&header_map, &key) < NANOCBOR_OK) {
            fprintf(stderr, "[suit-sig] malformed protected header key\n");
            return SUIT_AUTH_INVALID_INPUT;
        }
        if (key == SUIT_COSE_HEADER_ALG) {
            if (nanocbor_get_int64(&header_map, algorithm) < NANOCBOR_OK) {
                fprintf(stderr,
                        "[suit-sig] malformed algorithm header value\n");
                return SUIT_AUTH_INVALID_INPUT;
            }
            found = true;
        }
        else if (nanocbor_skip(&header_map) < NANOCBOR_OK) {
            fprintf(stderr, "[suit-sig] malformed protected header value\n");
            return SUIT_AUTH_INVALID_INPUT;
        }
    }

    if (!found) {
        fprintf(stderr,
                "[suit-sig] protected header is missing the algorithm id\n");
        return SUIT_AUTH_INVALID_INPUT;
    }
    return SUIT_AUTH_OK;
}

/* Sig_structure = ["Signature1", protected, external_aad, payload], RFC 9052 */
static int _build_sig_structure(uint8_t *buf, size_t buf_len,
                                const uint8_t *protected_header,
                                size_t protected_header_len,
                                const uint8_t *payload, size_t payload_len)
{
    static const uint8_t no_external_aad[1] = { 0 };
    nanocbor_encoder_t enc;

    nanocbor_encoder_init(&enc, buf, buf_len);
    nanocbor_fmt_array(&enc, 4);
    nanocbor_put_tstr(&enc, "Signature1");
    nanocbor_put_bstr(&enc, protected_header, protected_header_len);
    nanocbor_put_bstr(&enc, no_external_aad, 0);
    nanocbor_put_bstr(&enc, payload, payload_len);

    if (nanocbor_encoded_len(&enc) > buf_len) {
        return -1;
    }
    return (int)nanocbor_encoded_len(&enc);
}

suit_auth_result_t suit_signature_verify(const uint8_t *block, size_t block_len,
                                         const uint8_t *digest_encoded,
                                         size_t digest_encoded_len,
                                         const char *key_path)
{
    nanocbor_value_t block_value;
    nanocbor_value_t sign1;
    const uint8_t *protected_header = NULL;
    size_t protected_header_len = 0;
    const uint8_t *signature = NULL;
    size_t signature_len = 0;
    int64_t algorithm = 0;
    uint32_t tag = 0;

    nanocbor_decoder_init(&block_value, block, block_len);

    if (nanocbor_get_type(&block_value) == NANOCBOR_TYPE_TAG) {
        if (nanocbor_get_tag(&block_value, &tag) < NANOCBOR_OK
            || tag != SUIT_COSE_TAG_SIGN1) {
            fprintf(stderr,
                    "[suit-sig] unsupported authentication block tag: %"
                    PRIu32 "\n", tag);
            return SUIT_AUTH_UNSUPPORTED;
        }
    }

    if (nanocbor_enter_array(&block_value, &sign1) < NANOCBOR_OK) {
        fprintf(stderr, "[suit-sig] COSE_Sign1 is not an array\n");
        return SUIT_AUTH_INVALID_INPUT;
    }
    if (nanocbor_get_bstr(&sign1, &protected_header, &protected_header_len)
        < NANOCBOR_OK) {
        fprintf(stderr, "[suit-sig] missing protected header\n");
        return SUIT_AUTH_INVALID_INPUT;
    }

    suit_auth_result_t header_result = _protected_header_algorithm(
        protected_header, protected_header_len, &algorithm);
    if (header_result != SUIT_AUTH_OK) {
        return header_result;
    }
    fprintf(stderr, "[suit-sig] signature algorithm: %" PRId64 "\n", algorithm);

    if (nanocbor_skip(&sign1) < NANOCBOR_OK) {
        fprintf(stderr, "[suit-sig] malformed unprotected header\n");
        return SUIT_AUTH_INVALID_INPUT;
    }

    /* SUIT_Authentication_Block signs the sibling SUIT_Digest field either
     * as a detached (nil) payload or embedded directly; RFC 9052 4.2
     * permits both. Either way the signed content must be that digest
     * field, so an embedded payload is required to byte-match it. */
    if (nanocbor_get_null(&sign1) < NANOCBOR_OK) {
        const uint8_t *payload = NULL;
        size_t payload_len = 0;
        if (nanocbor_get_bstr(&sign1, &payload, &payload_len) < NANOCBOR_OK) {
            fprintf(stderr, "[suit-sig] malformed payload\n");
            return SUIT_AUTH_INVALID_INPUT;
        }
        if (payload_len != digest_encoded_len
            || memcmp(payload, digest_encoded, payload_len) != 0) {
            fprintf(stderr,
                    "[suit-sig] embedded payload does not match the "
                    "manifest digest field\n");
            return SUIT_AUTH_DIGEST_MISMATCH;
        }
    }
    if (nanocbor_get_bstr(&sign1, &signature, &signature_len) < NANOCBOR_OK) {
        fprintf(stderr, "[suit-sig] missing signature bytes\n");
        return SUIT_AUTH_INVALID_INPUT;
    }

    if (algorithm != SUIT_COSE_ALG_ES256) {
        fprintf(stderr, "[suit-sig] unsupported signature algorithm: %"
                PRId64 "\n", algorithm);
        return SUIT_AUTH_UNSUPPORTED;
    }

    uint8_t sig_structure[SUIT_SIG_STRUCTURE_MAX_BYTES];
    int sig_structure_len = _build_sig_structure(
        sig_structure, sizeof(sig_structure), protected_header,
        protected_header_len, digest_encoded, digest_encoded_len);
    if (sig_structure_len < 0) {
        fprintf(stderr, "[suit-sig] Sig_structure too large for internal buffer\n");
        return SUIT_AUTH_CRYPTO_ERROR;
    }

    EVP_PKEY *key = _load_public_key(key_path);
    if (!key) {
        return SUIT_AUTH_CRYPTO_ERROR;
    }
    suit_auth_result_t result = _verify_es256(
        key, sig_structure, (size_t)sig_structure_len, signature, signature_len);
    EVP_PKEY_free(key);

    if (result == SUIT_AUTH_OK) {
        fprintf(stderr, "[suit-sig] signature verified\n");
    }
    else {
        fprintf(stderr, "[suit-sig] signature verification failed (%d)\n",
                result);
    }
    return result;
}
