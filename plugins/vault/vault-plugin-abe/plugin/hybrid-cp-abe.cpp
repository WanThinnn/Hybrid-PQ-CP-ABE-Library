#include "hybrid_pq_cp_abe/common-utils.h"
#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/osrng.h>
#include <cryptopp/sha.h>
#include <cryptopp/sha3.h>

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <stdexcept>
#include <cstring>

#include "hybrid_pq_cp_abe/hybrid-pq-cp-abe.h"

// ============================================================================
// Utility API Implementations
// ============================================================================

const char* getVersion(void)
{
    return HybridCPABE::LIB_VERSION;
}

const char* getErrorMessage(int errorCode)
{
    switch (errorCode) {
        case HCPABE_SUCCESS:            return "Success";
        case HCPABE_ERR_FILE_NOT_FOUND: return "File not found";
        case HCPABE_ERR_INVALID_KEY:    return "Invalid key";
        case HCPABE_ERR_POLICY_MISMATCH: return "Policy mismatch - attributes do not satisfy policy";
        case HCPABE_ERR_CRYPTO_FAILED:  return "Cryptographic operation failed";
        case HCPABE_ERR_INVALID_PARAM:  return "Invalid parameter";
        case HCPABE_ERR_MEMORY:         return "Memory allocation failed";
        case HCPABE_ERR_UNSUPPORTED_FORMAT: return "Unsupported format";
        case HCPABE_ERR_VERSION_MISMATCH: return "Ciphertext format version mismatch";
        case HCPABE_ERR_SIGNATURE_INVALID: return "Signature invalid";
        default:                        return "Unknown error";
    }
}

void freeBuffer(unsigned char *buffer)
{
    if (buffer != nullptr) {
        free(buffer);
    }
}

// ============================================================================
// Scheme-aware CP-ABE Dispatch
// ============================================================================

// ============================================================================
// Buffer-based Setup & KeyGen Implementation
// ============================================================================

int setup_with_scheme(const char *path, CPABEScheme scheme)
{
    switch (scheme) {
        case CPABE_SCHEME_AC17: return ac17_setup(path);
        case CPABE_SCHEME_TKN20: return tkn20_setup(path);
        default: return HCPABE_ERR_INVALID_PARAM;
    }
}

int setup(const char *path)
{
    // Backward compatibility: default to AC17
    return setup_with_scheme(path, CPABE_SCHEME_AC17);
}


int hybrid_cpabe_setupBuffer_with_scheme(
    unsigned char **pkBuffer, size_t *pkLen,
    unsigned char **mskBuffer, size_t *mskLen,
    CPABEScheme scheme)
{
    if (!pkBuffer || !pkLen || !mskBuffer || !mskLen) return HCPABE_ERR_INVALID_PARAM;
    if (scheme == CPABE_SCHEME_AC17) {
        return ac17_setupBuffer(pkBuffer, pkLen, mskBuffer, mskLen);
    } else if (scheme == CPABE_SCHEME_TKN20) {
        return tkn20_setupBuffer(pkBuffer, pkLen, mskBuffer, mskLen);
    }
    return HCPABE_ERR_INVALID_PARAM;
}

int generateSecretKey_with_scheme(const char *masterKeyFile, const char *attributes, const char *privateKeyFile, CPABEScheme scheme)
{
    switch (scheme) {
        case CPABE_SCHEME_AC17: return ac17_genkey(masterKeyFile, attributes, privateKeyFile);
        case CPABE_SCHEME_TKN20: return tkn20_genkey(masterKeyFile, attributes, privateKeyFile);
        default: return HCPABE_ERR_INVALID_PARAM;
    }
}

int generateSecretKey(const char *masterKeyFile, const char *attributes, const char *privateKeyFile)
{
    return generateSecretKey_with_scheme(masterKeyFile, attributes, privateKeyFile, CPABE_SCHEME_AC17);
}

int hybrid_cpabe_genkeyBuffer_with_scheme(
    const unsigned char *mskBuffer, size_t mskLen,
    const char *attributes,
    unsigned char **skBuffer, size_t *skLen,
    CPABEScheme scheme)
{
    if (!mskBuffer || mskLen == 0 || !attributes || !skBuffer || !skLen) return HCPABE_ERR_INVALID_PARAM;
    if (scheme == CPABE_SCHEME_AC17) {
        return ac17_genkeyBuffer(mskBuffer, mskLen, attributes, skBuffer, skLen);
    } else if (scheme == CPABE_SCHEME_TKN20) {
        return tkn20_genkeyBuffer(mskBuffer, mskLen, attributes, skBuffer, skLen);
    }
    return HCPABE_ERR_INVALID_PARAM;
}

// ============================================================================
// Core Encryption Logic (Scheme agnostic)
// ============================================================================

int hybrid_cpabe_encryptBuffer_with_scheme(
    const unsigned char *publicKey, size_t pkLen,
    const unsigned char *plaintext, size_t ptLen,
    const char *policy,
    unsigned char **ciphertext, size_t *ctLen,
    CPABEScheme scheme)
{
    std::string aesKey;
    std::string randomKeyStr;
    
    try
    {
        if (!publicKey || !plaintext || !policy || !ciphertext || !ctLen)
            return HCPABE_ERR_INVALID_PARAM;
            
        CryptoPP::AutoSeededRandomPool prng;
        CryptoPP::Integer randomKey(prng, 12288);
        randomKey.Encode(CryptoPP::StringSink(randomKeyStr).Ref(), randomKey.MinEncodedSize());

        unsigned char *encryptedAbeKey = nullptr;
        size_t encryptedAbeKeyLen = 0;
        int abeRes = HCPABE_ERR_INVALID_PARAM;
        
        switch (scheme) {
            case CPABE_SCHEME_AC17:
                abeRes = ac17_encapsulate_key(publicKey, pkLen, policy, 
                                              reinterpret_cast<const unsigned char*>(randomKeyStr.data()), 
                                              randomKeyStr.size(), 
                                              &encryptedAbeKey, &encryptedAbeKeyLen);
                break;
            case CPABE_SCHEME_TKN20:
                abeRes = tkn20_encapsulate_key(publicKey, pkLen, policy, 
                                              reinterpret_cast<const unsigned char*>(randomKeyStr.data()), 
                                              randomKeyStr.size(), 
                                              &encryptedAbeKey, &encryptedAbeKeyLen);
                break;
        }

        if (abeRes != HCPABE_SUCCESS)
        {
            secureWipe(&randomKeyStr[0], randomKeyStr.size());
            return abeRes;
        }

        // AES Key generation
        CryptoPP::SHA3_256 hash;
        aesKey.resize(hash.DigestSize(), 0);
        hash.Update(reinterpret_cast<const CryptoPP::byte *>(randomKeyStr.data()), randomKeyStr.size());
        hash.Final(reinterpret_cast<CryptoPP::byte *>(&aesKey[0]));

        // Prepare AAD
        CryptoPP::byte iv[HybridCPABE::GCM_IV_SIZE];
        prng.GenerateBlock(iv, sizeof(iv));

        std::string aad;
        aad.push_back(static_cast<char>(HybridCPABE::FORMAT_VERSION_2)); // v2 header
        aad.push_back(static_cast<char>(scheme)); // scheme identifier byte
        aad.append(reinterpret_cast<const char *>(iv), sizeof(iv));
        uint64_t lenEncryptedKey = encryptedAbeKeyLen;
        aad.append(reinterpret_cast<const char *>(&lenEncryptedKey), sizeof(lenEncryptedKey));
        aad.append(reinterpret_cast<const char *>(encryptedAbeKey), encryptedAbeKeyLen);

        freeBuffer(encryptedAbeKey);

        unsigned char *aesCiphertext = nullptr;
        size_t aesCtLen = 0;
        int aesRes = aes_gcm_encrypt(
            reinterpret_cast<const unsigned char*>(aesKey.data()), aesKey.size(),
            iv, sizeof(iv),
            plaintext, ptLen,
            reinterpret_cast<const unsigned char*>(aad.data()), aad.size(),
            &aesCiphertext, &aesCtLen
        );

        if (aesRes != HCPABE_SUCCESS) {
            secureWipe(&aesKey[0], aesKey.size());
            secureWipe(&randomKeyStr[0], randomKeyStr.size());
            return aesRes;
        }

        // Combine parts
        std::string combined;
        combined.append(aad);
        combined.append(reinterpret_cast<const char*>(aesCiphertext), aesCtLen);
        freeBuffer(aesCiphertext);

        // Allocate and copy back
        *ctLen = combined.size();
        *ciphertext = (unsigned char *)malloc(*ctLen);
        if (!*ciphertext)
        {
            secureWipe(&aesKey[0], aesKey.size());
            secureWipe(&randomKeyStr[0], randomKeyStr.size());
            return HCPABE_ERR_MEMORY;
        }
        std::memcpy(*ciphertext, combined.data(), *ctLen);

        secureWipe(&aesKey[0], aesKey.size());
        secureWipe(&randomKeyStr[0], randomKeyStr.size());
        return HCPABE_SUCCESS;
    }
    catch (const std::exception &ex)
    {
        std::cerr << "Buffer encryption exception: " << ex.what() << std::endl;
        secureWipe(&aesKey[0], aesKey.size());
        secureWipe(&randomKeyStr[0], randomKeyStr.size());
        return HCPABE_ERR_CRYPTO_FAILED;
    }
}

int hybrid_cpabe_encryptBuffer(
    const unsigned char *publicKey, size_t pkLen,
    const unsigned char *plaintext, size_t ptLen,
    const char *policy,
    unsigned char **ciphertext, size_t *ctLen)
{
    // Call with legacy mode (AC17) but save under format_version_2 (containing AC17 scheme byte)
    // because if this function is called, we still want to encrypt correctly and be compatible. However,
    // to be fully compatible with old ciphertexts, we should create a FORMAT_VERSION (0x01) ciphertext.
    // To keep the code cleaner, here if the user does not specify, we fallback to AC17.
    // Actually the encryptBuffer_with_scheme uses FORMAT_VERSION_2.
    // New format: FORMAT_VERSION_2 (1 byte) || Scheme ID (1 byte) || CP-ABE Ciphertext Length (8 bytes) || IV (12 bytes) || Encrypted CP-ABE Key || GCM Tag || AES Ciphertext. Decrypt will recognize v2 and AC17 scheme.
    return hybrid_cpabe_encryptBuffer_with_scheme(publicKey, pkLen, plaintext, ptLen, policy, ciphertext, ctLen, CPABE_SCHEME_AC17);
}

int hybrid_cpabe_encrypt_with_scheme(const char *publicKeyFile, const char *plaintextFile, const char *policy, const char *ciphertextFile, CPABEScheme scheme)
{
    unsigned char *pkData = nullptr;
    size_t pkLen = 0;
    int loadRes = HCPABE_ERR_FILE_NOT_FOUND;

    switch (scheme) {
        case CPABE_SCHEME_AC17: loadRes = ac17_load_pk(publicKeyFile, &pkData, &pkLen); break;
        case CPABE_SCHEME_TKN20: loadRes = tkn20_load_pk(publicKeyFile, &pkData, &pkLen); break;
    }

    if (loadRes != HCPABE_SUCCESS) return loadRes;

    std::ifstream file(plaintextFile, std::ios::binary);
    if (!file)
    {
        freeBuffer(pkData);
        return HCPABE_ERR_FILE_NOT_FOUND;
    }
    std::string plaintext((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();

    unsigned char *ctData = nullptr;
    size_t ctLen = 0;
    
    int res = hybrid_cpabe_encryptBuffer_with_scheme(
        pkData, pkLen,
        reinterpret_cast<const unsigned char*>(plaintext.data()), plaintext.size(),
        policy,
        &ctData, &ctLen,
        scheme
    );

    freeBuffer(pkData);

    if (res == HCPABE_SUCCESS) {
        try {
            CryptoPP::FileSink fileSink(ciphertextFile, true);
            fileSink.Put(reinterpret_cast<const CryptoPP::byte *>(ctData), ctLen);
            fileSink.MessageEnd();
            std::cout << "Encryption successful!" << std::endl;
        }
        catch (...) {
            res = HCPABE_ERR_FILE_NOT_FOUND;
        }
        freeBuffer(ctData);
    }
    
    return res;
}

int hybrid_cpabe_encrypt(const char *publicKeyFile, const char *plaintextFile, const char *policy, const char *ciphertextFile)
{
    return hybrid_cpabe_encrypt_with_scheme(publicKeyFile, plaintextFile, policy, ciphertextFile, CPABE_SCHEME_AC17);
}

// ============================================================================
// Core Decryption Logic (Auto-detect scheme)
// ============================================================================

int hybrid_cpabe_decryptBuffer(
    const unsigned char *privateKey, size_t skLen,
    const unsigned char *ciphertext, size_t ctLen,
    unsigned char **plaintext, size_t *ptLen)
{
    std::string aesKey;
    std::string recoveredKeyStr;
    
    try
    {
        if (!privateKey || !ciphertext || !plaintext || !ptLen)
            return HCPABE_ERR_INVALID_PARAM;
            
        std::string decodedCiphertext(reinterpret_cast<const char*>(ciphertext), ctLen);

        if (decodedCiphertext.empty())
            return HCPABE_ERR_CRYPTO_FAILED;
            
        uint8_t version = static_cast<uint8_t>(decodedCiphertext[0]);
        CPABEScheme scheme = CPABE_SCHEME_AC17;
        uint64_t offset = 1;

        if (version == HybridCPABE::FORMAT_VERSION_2) {
            // Version 2 has scheme byte
            if (decodedCiphertext.size() < offset + 1)
                return HCPABE_ERR_CRYPTO_FAILED;
            scheme = static_cast<CPABEScheme>(decodedCiphertext[1]);
            offset += 1;
        } else if (version == HybridCPABE::FORMAT_VERSION) {
            // Legacy version implies AC17
            scheme = CPABE_SCHEME_AC17;
        } else {
            return HCPABE_ERR_VERSION_MISMATCH;
        }
            
        if (decodedCiphertext.size() < offset + HybridCPABE::GCM_IV_SIZE)
            return HCPABE_ERR_CRYPTO_FAILED;
        
        CryptoPP::byte iv[HybridCPABE::GCM_IV_SIZE];
        std::memcpy(iv, decodedCiphertext.data() + offset, sizeof(iv));
        offset += sizeof(iv);
        
        if (decodedCiphertext.size() < offset + sizeof(uint64_t))
            return HCPABE_ERR_CRYPTO_FAILED;
        uint64_t lenEncryptedKey;
        std::memcpy(&lenEncryptedKey, decodedCiphertext.data() + offset, sizeof(lenEncryptedKey));
        offset += sizeof(lenEncryptedKey);
        
        if (decodedCiphertext.size() < offset + lenEncryptedKey)
            return HCPABE_ERR_CRYPTO_FAILED;
        std::string encryptedKeyB = decodedCiphertext.substr(offset, lenEncryptedKey);
        offset += lenEncryptedKey;
        std::string aesCiphertext = decodedCiphertext.substr(offset);

        // ABE Decrypt Random Key
        unsigned char *recoveredAbeKey = nullptr;
        size_t recoveredAbeKeyLen = 0;
        int abeRes = HCPABE_ERR_INVALID_PARAM;

        switch (scheme) {
            case CPABE_SCHEME_AC17:
                abeRes = ac17_decapsulate_key(privateKey, skLen, 
                                              reinterpret_cast<const unsigned char*>(encryptedKeyB.data()), 
                                              encryptedKeyB.size(), 
                                              &recoveredAbeKey, &recoveredAbeKeyLen);
                break;
            case CPABE_SCHEME_TKN20:
                abeRes = tkn20_decapsulate_key(privateKey, skLen, 
                                               reinterpret_cast<const unsigned char*>(encryptedKeyB.data()), 
                                               encryptedKeyB.size(), 
                                               &recoveredAbeKey, &recoveredAbeKeyLen);
                break;
        }

        if (abeRes != HCPABE_SUCCESS)
            return abeRes;

        // Extract and hash random key
        CryptoPP::Integer recoveredRandomKey(reinterpret_cast<const CryptoPP::byte *>(recoveredAbeKey), recoveredAbeKeyLen);
        freeBuffer(recoveredAbeKey);

        CryptoPP::SHA3_256 hash;
        aesKey.resize(hash.DigestSize(), 0);
        recoveredRandomKey.Encode(CryptoPP::StringSink(recoveredKeyStr).Ref(), recoveredRandomKey.MinEncodedSize());
        hash.Update(reinterpret_cast<const CryptoPP::byte *>(recoveredKeyStr.data()), recoveredKeyStr.size());
        hash.Final(reinterpret_cast<CryptoPP::byte *>(&aesKey[0]));

        // Prepare AAD
        std::string aad = decodedCiphertext.substr(0, offset);

        unsigned char *recoveredPt = nullptr;
        size_t recoveredPtLen = 0;
        int decRes = aes_gcm_decrypt(
            reinterpret_cast<const unsigned char*>(aesKey.data()), aesKey.size(),
            iv, sizeof(iv),
            reinterpret_cast<const unsigned char*>(aesCiphertext.data()), aesCiphertext.size(),
            reinterpret_cast<const unsigned char*>(aad.data()), aad.size(),
            &recoveredPt, &recoveredPtLen
        );

        if (decRes != HCPABE_SUCCESS)
        {
            secureWipe(&aesKey[0], aesKey.size());
            secureWipe(&recoveredKeyStr[0], recoveredKeyStr.size());
            return decRes;
        }
        std::string recovered(reinterpret_cast<const char*>(recoveredPt), recoveredPtLen);
        free(recoveredPt);

        // Output plaintext
        *ptLen = recovered.size();
        *plaintext = (unsigned char *)malloc(*ptLen);
        if (!*plaintext)
        {
            secureWipe(&aesKey[0], aesKey.size());
            secureWipe(&recoveredKeyStr[0], recoveredKeyStr.size());
            return HCPABE_ERR_MEMORY;
        }
        std::memcpy(*plaintext, recovered.data(), *ptLen);

        secureWipe(&aesKey[0], aesKey.size());
        secureWipe(&recoveredKeyStr[0], recoveredKeyStr.size());
        
        return HCPABE_SUCCESS;
    }
    catch (const std::exception &ex)
    {
        std::cerr << "Buffer decryption exception: " << ex.what() << std::endl;
        secureWipe(&aesKey[0], aesKey.size());
        secureWipe(&recoveredKeyStr[0], recoveredKeyStr.size());
        return HCPABE_ERR_CRYPTO_FAILED;
    }
}

int hybrid_cpabe_decrypt(const char *privateKeyFile, const char *ciphertextFile, const char *recovertextFile)
{
    try
    {
        std::string decodedCiphertext;
        try {
            CryptoPP::FileSource fileSource(ciphertextFile, true, new CryptoPP::StringSink(decodedCiphertext));
        }
        catch (...) {
            return HCPABE_ERR_FILE_NOT_FOUND;
        }

        if (decodedCiphertext.empty()) return HCPABE_ERR_CRYPTO_FAILED;

        // Auto-detect scheme from version
        uint8_t version = static_cast<uint8_t>(decodedCiphertext[0]);
        CPABEScheme scheme = CPABE_SCHEME_AC17;
        // Old format (AC17 only): FORMAT_VERSION (1 byte) || CP-ABE Ciphertext Length (8 bytes) || ...
        if (version == HybridCPABE::FORMAT_VERSION_2 && decodedCiphertext.size() > 1) {
            scheme = static_cast<CPABEScheme>(decodedCiphertext[1]);
        }

        unsigned char *skData = nullptr;
        size_t skLen = 0;
        int loadRes = HCPABE_ERR_FILE_NOT_FOUND;
        switch (scheme) {
            case CPABE_SCHEME_AC17: loadRes = ac17_load_sk(privateKeyFile, &skData, &skLen); break;
            case CPABE_SCHEME_TKN20: loadRes = tkn20_load_sk(privateKeyFile, &skData, &skLen); break;
        }

        if (loadRes != HCPABE_SUCCESS) return loadRes;

        unsigned char *ptData = nullptr;
        size_t ptLen = 0;

        int res = hybrid_cpabe_decryptBuffer(
            skData, skLen,
            reinterpret_cast<const unsigned char*>(decodedCiphertext.data()), decodedCiphertext.size(),
            &ptData, &ptLen
        );

        freeBuffer(skData);

        if (res == HCPABE_SUCCESS) {
            try {
                CryptoPP::FileSink fileSink(recovertextFile, true);
                fileSink.Put(reinterpret_cast<const CryptoPP::byte *>(ptData), ptLen);
                fileSink.MessageEnd();
                std::cout << "Decryption successful!" << std::endl;
            }
            catch (...) {
                res = HCPABE_ERR_FILE_NOT_FOUND;
            }
            freeBuffer(ptData);
        }

        return res;
    }
    catch (...)
    {
        return HCPABE_ERR_CRYPTO_FAILED;
    }
}

