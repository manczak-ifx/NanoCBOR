/*
 * SPDX-License-Identifier: CC0-1.0
 *
 * Regression test: real-world SUIT authentication blocks (e.g. produced by
 * the "embroider" manifest tool) carry the SUIT_Digest as an *embedded*
 * COSE_Sign1 payload rather than a detached (nil) one. suit_signature_verify()
 * currently rejects any non-nil payload with SUIT_AUTH_UNSUPPORTED, so a
 * validly signed, spec-conformant manifest fails authentication.
 *
 * This test builds such a block in-memory, signs it with a freshly
 * generated ES256 key, and asserts that verification succeeds against the
 * matching digest bytes. It currently FAILS against production code and
 * documents the defect described in the accompanying report; do not weaken
 * the assertions to make it pass.
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include "nanocbor/nanocbor.h"
#include "auth.h"
#include "suit_iana.h"
#include "suit_signature.h"

static int _generate_p256_keypair(EVP_PKEY **key)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0
        || EVP_PKEY_CTX_set_group_name(ctx, "P-256") <= 0
        || EVP_PKEY_keygen(ctx, key) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }
    EVP_PKEY_CTX_free(ctx);
    return 0;
}

static int _write_public_key(EVP_PKEY *key, const char *path)
{
    FILE *fp = fopen(path, "we");
    if (!fp) {
        return -1;
    }
    int ok = PEM_write_PUBKEY(fp, key) == 1;
    fclose(fp);
    return ok ? 0 : -1;
}

/* raw r||s -> DER SEQUENCE, mirroring what a real signer emits for COSE. */
static int _raw_from_der_ecdsa_signature(const uint8_t *der, size_t der_len,
                                         uint8_t *raw, size_t raw_len)
{
    const uint8_t *cur = der;
    ECDSA_SIG *sig = d2i_ECDSA_SIG(NULL, &cur, (long)der_len);
    if (!sig) {
        return -1;
    }
    const BIGNUM *r = NULL;
    const BIGNUM *s = NULL;
    ECDSA_SIG_get0(sig, &r, &s);
    size_t half = raw_len / 2;
    int ok = BN_bn2binpad(r, raw, (int)half) == (int)half
             && BN_bn2binpad(s, raw + half, (int)half) == (int)half;
    ECDSA_SIG_free(sig);
    return ok ? 0 : -1;
}

int main(void)
{
    int failures = 0;

    /* SUIT_Digest = [alg, digest-bytes]; content is arbitrary for this test. */
    static const uint8_t manifest_digest[32] = {
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    };
    uint8_t digest_struct[64];
    nanocbor_encoder_t denc;
    nanocbor_encoder_init(&denc, digest_struct, sizeof(digest_struct));
    nanocbor_fmt_array(&denc, 2);
    nanocbor_fmt_int(&denc, SUIT_COSE_ALG_SHA_256);
    nanocbor_put_bstr(&denc, manifest_digest, sizeof(manifest_digest));
    size_t digest_struct_len = nanocbor_encoded_len(&denc);
    assert(digest_struct_len <= sizeof(digest_struct));

    /* protected header = {1: -7} */
    uint8_t protected_header[8];
    nanocbor_encoder_t penc;
    nanocbor_encoder_init(&penc, protected_header, sizeof(protected_header));
    nanocbor_fmt_map(&penc, 1);
    nanocbor_fmt_int(&penc, SUIT_COSE_HEADER_ALG);
    nanocbor_fmt_int(&penc, SUIT_COSE_ALG_ES256);
    size_t protected_header_len = nanocbor_encoded_len(&penc);
    assert(protected_header_len <= sizeof(protected_header));

    /* Sig_structure = ["Signature1", protected, h'', payload=digest_struct] */
    uint8_t sig_structure[128];
    nanocbor_encoder_t senc;
    nanocbor_encoder_init(&senc, sig_structure, sizeof(sig_structure));
    nanocbor_fmt_array(&senc, 4);
    nanocbor_put_tstr(&senc, "Signature1");
    nanocbor_put_bstr(&senc, protected_header, protected_header_len);
    nanocbor_put_bstr(&senc, NULL, 0);
    nanocbor_put_bstr(&senc, digest_struct, digest_struct_len);
    size_t sig_structure_len = nanocbor_encoded_len(&senc);
    assert(sig_structure_len <= sizeof(sig_structure));

    EVP_PKEY *key = NULL;
    if (_generate_p256_keypair(&key) != 0) {
        fprintf(stderr, "FAIL: could not generate test EC key\n");
        return 1;
    }

    char key_path[] = "/tmp/suit_test_pub_XXXXXX";
    int fd = mkstemp(key_path);
    if (fd < 0 || _write_public_key(key, key_path) != 0) {
        fprintf(stderr, "FAIL: could not write test public key\n");
        return 1;
    }
    close(fd);

    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    uint8_t der_signature[80];
    size_t der_signature_len = sizeof(der_signature);
    int signed_ok = EVP_DigestSignInit(mctx, NULL, EVP_sha256(), NULL, key) == 1
        && EVP_DigestSign(mctx, der_signature, &der_signature_len,
                          sig_structure, sig_structure_len) == 1;
    EVP_MD_CTX_free(mctx);
    if (!signed_ok) {
        fprintf(stderr, "FAIL: could not sign test Sig_structure\n");
        return 1;
    }

    uint8_t raw_signature[SUIT_ECDSA_P256_SIGNATURE_BYTES];
    if (_raw_from_der_ecdsa_signature(der_signature, der_signature_len,
                                      raw_signature, sizeof(raw_signature))
        != 0) {
        fprintf(stderr, "FAIL: could not convert signature to raw r||s\n");
        return 1;
    }

    /* COSE_Sign1 with an *embedded* payload (not nil/detached), as produced
     * by real-world SUIT tooling. The authentication-wrapper array element
     * handed to suit_signature_verify() is the tag+array bytes directly
     * (auth.c has already stripped the enclosing bstr header). */
    uint8_t auth_block[288];
    nanocbor_encoder_t aenc;
    nanocbor_encoder_init(&aenc, auth_block, sizeof(auth_block));
    nanocbor_fmt_tag(&aenc, SUIT_COSE_TAG_SIGN1);
    nanocbor_fmt_array(&aenc, 4);
    nanocbor_put_bstr(&aenc, protected_header, protected_header_len);
    nanocbor_fmt_map(&aenc, 0);
    nanocbor_put_bstr(&aenc, digest_struct, digest_struct_len);
    nanocbor_put_bstr(&aenc, raw_signature, sizeof(raw_signature));
    size_t auth_block_len = nanocbor_encoded_len(&aenc);
    assert(auth_block_len <= sizeof(auth_block));

    suit_auth_result_t result = suit_signature_verify(
        auth_block, auth_block_len, digest_struct, digest_struct_len,
        key_path);

    remove(key_path);
    EVP_PKEY_free(key);

    if (result != SUIT_AUTH_OK) {
        fprintf(stderr,
                "FAIL: expected SUIT_AUTH_OK (0) for a validly signed "
                "embedded-payload COSE_Sign1, got %d\n", (int)result);
        failures++;
    }
    else {
        printf("ok: embedded-payload COSE_Sign1 verified\n");
    }

    printf("\n%d assertion(s) failed\n", failures);
    return failures ? 1 : 0;
}
