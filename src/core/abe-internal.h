#ifndef ABE_INTERNAL_H
#define ABE_INTERNAL_H

// Private implementation shared by core files. This header is not installed.
#include "hybrid_pq_cp_abe/hybrid-pq-cp-abe.h"
#include "hybrid_pq_cp_abe/common-utils.h"
#include <cryptopp/osrng.h>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <limits>
#include <memory>
#include <stdexcept>

// Length metadata is implemented beside the ML-DSA primitives in crypto/ml-dsa.cpp.
size_t ml_dsa_87_public_key_size();
size_t ml_dsa_87_secret_key_size();
size_t ml_dsa_87_signature_size();

int setup_with_scheme_impl(const char *path, CPABEScheme scheme);

int setup_impl(const char *path);

int hybrid_cpabe_setupBuffer_with_scheme_impl(unsigned char **pkBuffer, size_t *pkLen, unsigned char **mskBuffer,
                                              size_t *mskLen, CPABEScheme scheme);

int hybrid_cpabe_setup_with_pqc_scheme_impl(const char *path, CPABEScheme scheme);

int hybrid_cpabe_setup_with_pqc_impl(const char *path);

int hybrid_cpabe_setupBuffer_with_pqc_scheme_impl(unsigned char **abePkBuffer, size_t *abePkLen,
                                                  unsigned char **abeMskBuffer, size_t *abeMskLen,
                                                  unsigned char **pqcPkBuffer, size_t *pqcPkLen,
                                                  unsigned char **pqcMskBuffer, size_t *pqcMskLen, CPABEScheme scheme);

int generateSecretKey_with_scheme_impl(const char *masterKeyFile, const char *attributes, const char *privateKeyFile,
                                       CPABEScheme scheme);

int generateSecretKey_impl(const char *masterKeyFile, const char *attributes, const char *privateKeyFile);

int hybrid_cpabe_genkeyBuffer_with_scheme_impl(const unsigned char *mskBuffer, size_t mskLen, const char *attributes,
                                               unsigned char **skBuffer, size_t *skLen, CPABEScheme scheme);

int hybrid_cpabe_encryptBuffer_with_scheme_impl(const unsigned char *publicKey, size_t pkLen,
                                                const unsigned char *plaintext, size_t ptLen, const char *policy,
                                                unsigned char **ciphertext, size_t *ctLen, CPABEScheme scheme);

int hybrid_cpabe_encryptBuffer_impl(const unsigned char *publicKey, size_t pkLen, const unsigned char *plaintext,
                                    size_t ptLen, const char *policy, unsigned char **ciphertext, size_t *ctLen);

int hybrid_cpabe_encrypt_with_scheme_impl(const char *publicKeyFile, const char *plaintextFile, const char *policy,
                                          const char *ciphertextFile, CPABEScheme scheme);

int hybrid_cpabe_encrypt_impl(const char *publicKeyFile, const char *plaintextFile, const char *policy,
                              const char *ciphertextFile);

int hybrid_cpabe_encryptBuffer_and_sign_with_scheme_impl(const unsigned char *publicKey, size_t pkLen,
                                                         const unsigned char *pqcPrivKey, size_t pqcPrivLen,
                                                         const unsigned char *plaintext, size_t ptLen,
                                                         const char *policy, unsigned char **ciphertext, size_t *ctLen,
                                                         CPABEScheme scheme);

int hybrid_cpabe_encryptBuffer_and_sign_impl(const unsigned char *publicKey, size_t pkLen,
                                             const unsigned char *pqcPrivKey, size_t pqcPrivLen,
                                             const unsigned char *plaintext, size_t ptLen, const char *policy,
                                             unsigned char **ciphertext, size_t *ctLen);

int hybrid_cpabe_encrypt_and_sign_with_scheme_impl(const char *publicKeyFile, const char *pqcPrivateKeyFile,
                                                   const char *plaintextFile, const char *policy,
                                                   const char *ciphertextFile, CPABEScheme scheme);

int hybrid_cpabe_encrypt_and_sign_impl(const char *publicKeyFile, const char *pqcPrivateKeyFile,
                                       const char *plaintextFile, const char *policy, const char *ciphertextFile);

int hybrid_cpabe_decryptBuffer_impl(const unsigned char *privateKey, size_t skLen, const unsigned char *ciphertext,
                                    size_t ctLen, unsigned char **plaintext, size_t *ptLen);

int hybrid_cpabe_decrypt_impl(const char *privateKeyFile, const char *ciphertextFile, const char *recovertextFile);

int hybrid_cpabe_decryptBuffer_and_verify_impl(const unsigned char *privateKey, size_t skLen,
                                               const unsigned char *pqcPubKey, size_t pqcPubLen,
                                               const unsigned char *ciphertext, size_t ctLen, unsigned char **plaintext,
                                               size_t *ptLen);

int hybrid_cpabe_decrypt_and_verify_impl(const char *privateKeyFile, const char *pqcPublicKeyFile,
                                         const char *ciphertextFile, const char *recovertextFile);

#endif // ABE_INTERNAL_H
