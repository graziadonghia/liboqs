/* C program to test dilithium and SPHINCS+ key generation, signing and verification */ 
#include <oqs/oqs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DEBUG_PRINT 0


// Function to print a byte array in hex format
void print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

void test_dilithium() {
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_dilithium_2); // define new signature object
    if (sig == NULL) {
        fprintf(stderr, "OQS_SIG_alg_dilithium_2 not supported\n");
        exit(EXIT_FAILURE);
    }
    uint8_t *public_key = malloc(sig->length_public_key);
    uint8_t *secret_key = malloc(sig->length_secret_key);
    uint8_t *message = (uint8_t *)"test message";
    uint8_t *signature = malloc(sig->length_signature);
    size_t message_len = strlen((char *)message);
    size_t signature_len;

    if (OQS_SUCCESS != OQS_SIG_keypair(sig, public_key, secret_key)) {
        fprintf(stderr, "OQS_SIG_keypair failed\n");
        exit(EXIT_FAILURE);
    }

#if DEBUG_PRINT
    // Print public and secret keys
    print_hex("Dilithium Public Key", public_key, sig->length_public_key);
    print_hex("Dilithium Secret Key", secret_key, sig->length_secret_key);
#endif

    if (OQS_SUCCESS != OQS_SIG_sign(sig, signature, &signature_len, message, message_len, secret_key)) {
        fprintf(stderr, "OQS_SIG_sign failed\n");
        exit(EXIT_FAILURE);
    }

#if DEBUG_PRINT
    // Print message and signature
    print_hex("Message", message, message_len);
    print_hex("Dilithium Signature", signature, signature_len);
#endif

    if (OQS_SUCCESS != OQS_SIG_verify(sig, message, message_len, signature, signature_len, public_key)) {
        fprintf(stderr, "OQS_SIG_verify failed\n");
        exit(EXIT_FAILURE);
    }



    printf("Dilithium test passed\n");

    OQS_SIG_free(sig);
    free(public_key);
    free(secret_key);
    free(signature);
}

void test_sphincs() {
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_sphincs_sha2_256f_simple);
    if (sig == NULL) {
        fprintf(stderr, "OQS_SIG_alg_sphincs_sha2_256f_simple not supported\n");
        exit(EXIT_FAILURE);
    }
    uint8_t *public_key = malloc(sig->length_public_key);
    uint8_t *secret_key = malloc(sig->length_secret_key);
    uint8_t *message = (uint8_t *)"test message";
    uint8_t *signature = malloc(sig->length_signature);
    size_t message_len = strlen((char *)message);
    size_t signature_len;

    if (OQS_SUCCESS != OQS_SIG_keypair(sig, public_key, secret_key)) {
        fprintf(stderr, "OQS_SIG_keypair failed\n");
        exit(EXIT_FAILURE);
    }

#if DEBUG_PRINT
    // Print public and secret keys
    print_hex("SPHINCS+ Public Key", public_key, sig->length_public_key);
    print_hex("SPHINCS+ Secret Key", secret_key, sig->length_secret_key);

#endif

    if (OQS_SUCCESS != OQS_SIG_sign(sig, signature, &signature_len, message, message_len, secret_key)) {
        fprintf(stderr, "OQS_SIG_sign failed\n");
        exit(EXIT_FAILURE);
    }

#if DEBUG_PRINT
    // Print message and signature
    print_hex("Message", message, message_len);
    print_hex("SPHINCS+ Signature", signature, signature_len);

#endif
    if (OQS_SUCCESS != OQS_SIG_verify(sig, message, message_len, signature, signature_len, public_key)) {
        fprintf(stderr, "OQS_SIG_verify failed\n");
        exit(EXIT_FAILURE);
    }

    printf("SPHINCS+ test passed\n");

    OQS_SIG_free(sig);
    free(public_key);
    free(secret_key);
    free(signature);
}

int main() {
    test_dilithium();
    test_sphincs();
    return 0;
}
