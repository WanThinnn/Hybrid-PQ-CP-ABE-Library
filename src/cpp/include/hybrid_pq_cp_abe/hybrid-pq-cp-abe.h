#ifndef HYBRID_PQ_CP_ABE_H
#define HYBRID_PQ_CP_ABE_H

#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>
#include "cpabe-scheme.h"

#ifdef _WIN32
#ifdef BUILD_DLL
// When building (exporting) the DLL library
#define LIB_API __declspec(dllexport)
#elif defined(USE_DLL)
// When using (importing) the DLL library
#define LIB_API __declspec(dllimport)
#else
// When using the static library
#define LIB_API
#endif
#else
// Export public functions for other OS (Linux/macOS)
#define LIB_API __attribute__((visibility("default")))
#endif

// ============================================================================
// Constants
// ============================================================================
namespace HybridCPABE {
    constexpr size_t GCM_IV_SIZE = 12;          // 96-bit theo NIST SP 800-38D
    constexpr size_t AES_KEY_SIZE = 32;         // 256-bit AES key
    constexpr uint8_t FORMAT_VERSION = 0x01;    // Ciphertext format version
    constexpr uint8_t FORMAT_VERSION_2 = 0x02;  // V2 format with scheme indicator
    const char* const LIB_VERSION = "4.0.0";
    const char* const DEFAULT_KEY_FORMAT = "Base64";
}

// ============================================================================
// Error Codes
// ============================================================================
typedef enum {
    HCPABE_SUCCESS = 0,
    HCPABE_ERR_FILE_NOT_FOUND = -1,
    HCPABE_ERR_INVALID_KEY = -2,
    HCPABE_ERR_POLICY_MISMATCH = -3,
    HCPABE_ERR_CRYPTO_FAILED = -4,
    HCPABE_ERR_INVALID_PARAM = -5,
    HCPABE_ERR_MEMORY = -6,
    HCPABE_ERR_UNSUPPORTED_FORMAT = -7,
    HCPABE_ERR_VERSION_MISMATCH = -8,
    HCPABE_ERR_SIGNATURE_INVALID = -9
} HCPABEError;

// ============================================================================
// C API - File-based Operations
// ============================================================================
extern "C"
{
    // Initialize system - create Master Key and Public Key
    LIB_API int setup(const char *path);
    
    // Setup with scheme selection
    LIB_API int setup_with_scheme(const char *path, CPABEScheme scheme);
    
    // Setup + PQC with scheme selection
    LIB_API int hybrid_cpabe_setup_with_pqc_scheme(const char *path, CPABEScheme scheme);
    
    // Generate Private Key with scheme selection
    LIB_API int generateSecretKey_with_scheme(const char *masterKeyFile, 
                                               const char *attributes, 
                                               const char *privateKeyFile,
                                               CPABEScheme scheme);
    
    // Encrypt file with scheme selection
    LIB_API int hybrid_cpabe_encrypt_with_scheme(const char *publicKeyFile, 
                            const char *plaintextFile, 
                            const char *policy, 
                            const char *ciphertextFile,
                            CPABEScheme scheme);
    
    // Decrypt file (requires attributes satisfying the policy)
    LIB_API int hybrid_cpabe_decrypt(const char *privateKeyFile, 
                            const char *ciphertextFile, 
                            const char *recovertextFile);

    // Encrypt file with PQC signature
    LIB_API int hybrid_cpabe_encrypt_and_sign(const char *publicKeyFile, 
                            const char *pqcPrivateKeyFile,
                            const char *plaintextFile, 
                            const char *policy, 
                            const char *ciphertextFile);
    
    // Decrypt file and verify PQC signature
    LIB_API int hybrid_cpabe_decrypt_and_verify(const char *privateKeyFile, 
                            const char *pqcPublicKeyFile,
                            const char *ciphertextFile, 
                            const char *recovertextFile);

    // ========================================================================
    // Buffer-based Operations (New API)
    // ========================================================================
    
    // Encrypt from buffer
    LIB_API int hybrid_cpabe_encryptBuffer(
        const unsigned char *publicKey, size_t pkLen,
        const unsigned char *plaintext, size_t ptLen,
        const char *policy,
        unsigned char **ciphertext, size_t *ctLen
    );

    // Encrypt buffer with scheme selection
    LIB_API int hybrid_cpabe_encryptBuffer_with_scheme(
        const unsigned char *publicKey, size_t pkLen,
        const unsigned char *plaintext, size_t ptLen,
        const char *policy,
        unsigned char **ciphertext, size_t *ctLen,
        CPABEScheme scheme);
    
    // Encrypt + sign with scheme selection
    LIB_API int hybrid_cpabe_encrypt_and_sign_with_scheme(
        const char *publicKeyFile, 
        const char *pqcPrivateKeyFile,
        const char *plaintextFile, 
        const char *policy, 
        const char *ciphertextFile,
        CPABEScheme scheme);
    
    // Encrypt buffer + sign with scheme selection
    LIB_API int hybrid_cpabe_encryptBuffer_and_sign_with_scheme(
        const unsigned char *publicKey, size_t pkLen,
        const unsigned char *pqcPrivKey, size_t pqcPrivLen,
        const unsigned char *plaintext, size_t ptLen,
        const char *policy,
        unsigned char **ciphertext, size_t *ctLen,
        CPABEScheme scheme);
    
    // Decrypt from buffer
    LIB_API int hybrid_cpabe_decryptBuffer(
        const unsigned char *privateKey, size_t skLen,
        const unsigned char *ciphertext, size_t ctLen,
        unsigned char **plaintext, size_t *ptLen
    );
    
    
    // Decrypt from buffer and verify PQC signature
    LIB_API int hybrid_cpabe_decryptBuffer_and_verify(
        const unsigned char *privateKey, size_t skLen,
        const unsigned char *pqcPubKey, size_t pqcPubLen,
        const unsigned char *ciphertext, size_t ctLen,
        unsigned char **plaintext, size_t *ptLen
    );
    
    // ========================================================================
    // ML-DSA-87 Operations
    // ========================================================================
    
    LIB_API int ml_dsa_87_generate_keypair(unsigned char **pk, size_t *pk_len, unsigned char **sk, size_t *sk_len);
    LIB_API int ml_dsa_87_sign(const unsigned char *msg, size_t msg_len, const unsigned char *sk, unsigned char **sig, size_t *sig_len);
    LIB_API int ml_dsa_87_verify(const unsigned char *msg, size_t msg_len, const unsigned char *sig, size_t sig_len, const unsigned char *pk);
    
    // ========================================================================
    // Utility Functions
    // ========================================================================
    
    // Get library version
    LIB_API const char* getVersion(void);
    
    // Get error message from error code
    LIB_API const char* getErrorMessage(int errorCode);
    
    // Free buffer allocated by the library
    LIB_API void freeBuffer(unsigned char *buffer);
    // AES-GCM API functions (Separated from CP-ABE logic)
    LIB_API int aes_gcm_encrypt(
        const unsigned char* key, size_t key_len,
        const unsigned char* iv, size_t iv_len,
        const unsigned char* plaintext, size_t pt_len,
        const unsigned char* aad, size_t aad_len,
        unsigned char** ciphertext, size_t* ct_len);

    LIB_API int aes_gcm_decrypt(
        const unsigned char* key, size_t key_len,
        const unsigned char* iv, size_t iv_len,
        const unsigned char* ciphertext, size_t ct_len,
        const unsigned char* aad, size_t aad_len,
        unsigned char** plaintext, size_t* pt_len);

}

#endif // HYBRID_PQ_CP_ABE_H
