#include "hybrid_pq_cp_abe/hybrid-pq-cp-abe.h"
#include "abe-internal.h"

#ifdef _MSC_VER
#include <malloc.h>
#include <stdarg.h>
#include <stdio.h>

extern "C"
{
    void *__mingw_aligned_malloc(size_t size, size_t alignment)
    {
        return _aligned_malloc(size, alignment);
    }
    void __mingw_aligned_free(void *memblock)
    {
        _aligned_free(memblock);
    }
    int __mingw_fprintf(FILE *const file, const char *format, ...)
    {
        va_list args;
        va_start(args, format);
        int ret = vfprintf(file, format, args);
        va_end(args);
        return ret;
    }
}
#pragma comment(linker, "/alternatename:___chkstk_ms=__chkstk")
#endif

const char *getVersion(void)
{
    return HybridCPABE::LIB_VERSION;
}

const char *getErrorMessage(int errorCode)
{
    switch (errorCode)
    {
    case HCPABE_SUCCESS:
        return "Success";
    case HCPABE_ERR_FILE_NOT_FOUND:
        return "File not found";
    case HCPABE_ERR_INVALID_KEY:
        return "Invalid key";
    case HCPABE_ERR_POLICY_MISMATCH:
        return "Policy mismatch - attributes do not satisfy policy";
    case HCPABE_ERR_CRYPTO_FAILED:
        return "Cryptographic operation failed";
    case HCPABE_ERR_INVALID_PARAM:
        return "Invalid parameter";
    case HCPABE_ERR_MEMORY:
        return "Memory allocation failed";
    case HCPABE_ERR_UNSUPPORTED_FORMAT:
        return "Unsupported format";
    case HCPABE_ERR_VERSION_MISMATCH:
        return "Ciphertext format version mismatch";
    case HCPABE_ERR_SIGNATURE_INVALID:
        return "Signature invalid";
    default:
        return "Unknown error";
    }
}

void freeBuffer(unsigned char *buffer)
{
    if (buffer != nullptr)
    {
        free(buffer);
    }
}

int setup_with_scheme(const char *path, CPABEScheme scheme)
{
    return setup_with_scheme_impl(path, scheme);
}

int setup(const char *path)
{
    return setup_impl(path);
}

int hybrid_cpabe_setupBuffer_with_scheme(unsigned char **pkBuffer, size_t *pkLen, unsigned char **mskBuffer,
                                         size_t *mskLen, CPABEScheme scheme)
{
    return hybrid_cpabe_setupBuffer_with_scheme_impl(pkBuffer, pkLen, mskBuffer, mskLen, scheme);
}

int hybrid_cpabe_setup_with_pqc_scheme(const char *path, CPABEScheme scheme)
{
    return hybrid_cpabe_setup_with_pqc_scheme_impl(path, scheme);
}

int hybrid_cpabe_setup_with_pqc(const char *path)
{
    return hybrid_cpabe_setup_with_pqc_impl(path);
}

int hybrid_cpabe_setupBuffer_with_pqc_scheme(unsigned char **abePkBuffer, size_t *abePkLen,
                                             unsigned char **abeMskBuffer, size_t *abeMskLen,
                                             unsigned char **pqcPkBuffer, size_t *pqcPkLen,
                                             unsigned char **pqcMskBuffer, size_t *pqcMskLen, CPABEScheme scheme)
{
    return hybrid_cpabe_setupBuffer_with_pqc_scheme_impl(abePkBuffer, abePkLen, abeMskBuffer, abeMskLen, pqcPkBuffer,
                                                         pqcPkLen, pqcMskBuffer, pqcMskLen, scheme);
}

int generateSecretKey_with_scheme(const char *masterKeyFile, const char *attributes, const char *privateKeyFile,
                                  CPABEScheme scheme)
{
    return generateSecretKey_with_scheme_impl(masterKeyFile, attributes, privateKeyFile, scheme);
}

int generateSecretKey(const char *masterKeyFile, const char *attributes, const char *privateKeyFile)
{
    return generateSecretKey_impl(masterKeyFile, attributes, privateKeyFile);
}

int hybrid_cpabe_genkeyBuffer_with_scheme(const unsigned char *mskBuffer, size_t mskLen, const char *attributes,
                                          unsigned char **skBuffer, size_t *skLen, CPABEScheme scheme)
{
    return hybrid_cpabe_genkeyBuffer_with_scheme_impl(mskBuffer, mskLen, attributes, skBuffer, skLen, scheme);
}

int hybrid_cpabe_encryptBuffer_with_scheme(const unsigned char *publicKey, size_t pkLen, const unsigned char *plaintext,
                                           size_t ptLen, const char *policy, unsigned char **ciphertext, size_t *ctLen,
                                           CPABEScheme scheme)
{
    return hybrid_cpabe_encryptBuffer_with_scheme_impl(publicKey, pkLen, plaintext, ptLen, policy, ciphertext, ctLen,
                                                       scheme);
}

int hybrid_cpabe_encryptBuffer(const unsigned char *publicKey, size_t pkLen, const unsigned char *plaintext,
                               size_t ptLen, const char *policy, unsigned char **ciphertext, size_t *ctLen)
{
    return hybrid_cpabe_encryptBuffer_impl(publicKey, pkLen, plaintext, ptLen, policy, ciphertext, ctLen);
}

int hybrid_cpabe_encrypt_with_scheme(const char *publicKeyFile, const char *plaintextFile, const char *policy,
                                     const char *ciphertextFile, CPABEScheme scheme)
{
    return hybrid_cpabe_encrypt_with_scheme_impl(publicKeyFile, plaintextFile, policy, ciphertextFile, scheme);
}

int hybrid_cpabe_encrypt(const char *publicKeyFile, const char *plaintextFile, const char *policy,
                         const char *ciphertextFile)
{
    return hybrid_cpabe_encrypt_impl(publicKeyFile, plaintextFile, policy, ciphertextFile);
}

int hybrid_cpabe_encryptBuffer_and_sign_with_scheme(const unsigned char *publicKey, size_t pkLen,
                                                    const unsigned char *pqcPrivKey, size_t pqcPrivLen,
                                                    const unsigned char *plaintext, size_t ptLen, const char *policy,
                                                    unsigned char **ciphertext, size_t *ctLen, CPABEScheme scheme)
{
    return hybrid_cpabe_encryptBuffer_and_sign_with_scheme_impl(publicKey, pkLen, pqcPrivKey, pqcPrivLen, plaintext,
                                                                ptLen, policy, ciphertext, ctLen, scheme);
}

int hybrid_cpabe_encryptBuffer_and_sign(const unsigned char *publicKey, size_t pkLen, const unsigned char *pqcPrivKey,
                                        size_t pqcPrivLen, const unsigned char *plaintext, size_t ptLen,
                                        const char *policy, unsigned char **ciphertext, size_t *ctLen)
{
    return hybrid_cpabe_encryptBuffer_and_sign_impl(publicKey, pkLen, pqcPrivKey, pqcPrivLen, plaintext, ptLen, policy,
                                                    ciphertext, ctLen);
}

int hybrid_cpabe_encrypt_and_sign_with_scheme(const char *publicKeyFile, const char *pqcPrivateKeyFile,
                                              const char *plaintextFile, const char *policy, const char *ciphertextFile,
                                              CPABEScheme scheme)
{
    return hybrid_cpabe_encrypt_and_sign_with_scheme_impl(publicKeyFile, pqcPrivateKeyFile, plaintextFile, policy,
                                                          ciphertextFile, scheme);
}

int hybrid_cpabe_encrypt_and_sign(const char *publicKeyFile, const char *pqcPrivateKeyFile, const char *plaintextFile,
                                  const char *policy, const char *ciphertextFile)
{
    return hybrid_cpabe_encrypt_and_sign_impl(publicKeyFile, pqcPrivateKeyFile, plaintextFile, policy, ciphertextFile);
}

int hybrid_cpabe_decryptBuffer(const unsigned char *privateKey, size_t skLen, const unsigned char *ciphertext,
                               size_t ctLen, unsigned char **plaintext, size_t *ptLen)
{
    return hybrid_cpabe_decryptBuffer_impl(privateKey, skLen, ciphertext, ctLen, plaintext, ptLen);
}

int hybrid_cpabe_decrypt(const char *privateKeyFile, const char *ciphertextFile, const char *recovertextFile)
{
    return hybrid_cpabe_decrypt_impl(privateKeyFile, ciphertextFile, recovertextFile);
}

int hybrid_cpabe_decryptBuffer_and_verify(const unsigned char *privateKey, size_t skLen, const unsigned char *pqcPubKey,
                                          size_t pqcPubLen, const unsigned char *ciphertext, size_t ctLen,
                                          unsigned char **plaintext, size_t *ptLen)
{
    return hybrid_cpabe_decryptBuffer_and_verify_impl(privateKey, skLen, pqcPubKey, pqcPubLen, ciphertext, ctLen,
                                                      plaintext, ptLen);
}

int hybrid_cpabe_decrypt_and_verify(const char *privateKeyFile, const char *pqcPublicKeyFile,
                                    const char *ciphertextFile, const char *recovertextFile)
{
    return hybrid_cpabe_decrypt_and_verify_impl(privateKeyFile, pqcPublicKeyFile, ciphertextFile, recovertextFile);
}
