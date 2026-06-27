#include "hybrid_pq_cp_abe/hybrid-pq-cp-abe.h"
#include "hybrid_pq_cp_abe/cpabe-scheme.h"
#include "hybrid_pq_cp_abe/common-utils.h"

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <stdexcept>
#include <iomanip>
#include <algorithm>
#include <cstring>
#include <sys/stat.h>

#ifdef _MSC_VER
#include <malloc.h>
#include <stdarg.h>
#include <stdio.h>

extern "C" {
    void* __mingw_aligned_malloc(size_t size, size_t alignment) {
        return _aligned_malloc(size, alignment);
    }
    void __mingw_aligned_free(void* memblock) {
        _aligned_free(memblock);
    }
    int __mingw_fprintf(FILE* const file, const char* format, ...) {
        va_list args;
        va_start(args, format);
        int ret = vfprintf(file, format, args);
        va_end(args);
        return ret;
    }
}
#pragma comment(linker, "/alternatename:___chkstk_ms=__chkstk")
#endif

// ============================================================================
// Scheme-aware PQC API
// ============================================================================

int hybrid_cpabe_setup_with_pqc_scheme(const char *path, CPABEScheme scheme)
{
    // First run the regular CP-ABE setup
    int abeRes = setup_with_scheme(path, scheme);
    if (abeRes != HCPABE_SUCCESS) return abeRes;

    std::string strPath(path);
    std::string strFileFormat = HybridCPABE::DEFAULT_KEY_FORMAT;
    unsigned char *pqc_pub = nullptr, *pqc_priv = nullptr;
    size_t pqc_pub_len = 0, pqc_priv_len = 0;
    
    try
    {
        if (ml_dsa_87_generate_keypair(&pqc_pub, &pqc_pub_len, &pqc_priv, &pqc_priv_len) != HCPABE_SUCCESS) {
            throw std::runtime_error("Failed to generate PQC keypair.");
        }

        std::string pqcPubBase64, pqcSecBase64;
        CryptoPP::StringSource(pqc_pub, pqc_pub_len, true, new CryptoPP::Base64Encoder(new CryptoPP::StringSink(pqcPubBase64), false));
        CryptoPP::StringSource(pqc_priv, pqc_priv_len, true, new CryptoPP::Base64Encoder(new CryptoPP::StringSink(pqcSecBase64), false));

        std::string pqcMskPath, pqcPkPath;
        struct stat info;
        if (stat(strPath.c_str(), &info) == 0 && (info.st_mode & S_IFDIR)) {
            pqcMskPath = strPath + "/pqc_sk.key";
            pqcPkPath = strPath + "/pqc_pk.key";
        } else if (strPath.empty() || strPath.back() == '/' || strPath.back() == '\\') {
            pqcMskPath = strPath + "pqc_sk.key";
            pqcPkPath = strPath + "pqc_pk.key";
        } else {
            pqcMskPath = strPath + "_pqc_sk.key";
            pqcPkPath = strPath + "_pqc_pk.key";
        }

        if (strFileFormat == "JsonText" || strFileFormat == "HEX" || strFileFormat == "Base64")
        {
            bool pqcMsSaved = SaveFile(pqcMskPath, pqcSecBase64.c_str(), strFileFormat);
            bool pqcPbSaved = SaveFile(pqcPkPath, pqcPubBase64.c_str(), strFileFormat);
            
            if (pqc_pub) free(pqc_pub);
            if (pqc_priv) free(pqc_priv);
            
            if (!pqcMsSaved || !pqcPbSaved) return HCPABE_ERR_FILE_NOT_FOUND;
            
            std::cout << "PQC Setup completed successfully." << std::endl;
            return HCPABE_SUCCESS;
        }
        else
        {
            throw std::invalid_argument("Unsupported format.");
        }
    }
    catch (...) { 
        if (pqc_pub) free(pqc_pub);
        if (pqc_priv) free(pqc_priv);
        return HCPABE_ERR_CRYPTO_FAILED; 
    }
}

int hybrid_cpabe_setup_with_pqc(const char *path)
{
    return hybrid_cpabe_setup_with_pqc_scheme(path, CPABE_SCHEME_AC17);
}

int hybrid_cpabe_setupBuffer_with_pqc_scheme(
    unsigned char **abePkBuffer, size_t *abePkLen,
    unsigned char **abeMskBuffer, size_t *abeMskLen,
    unsigned char **pqcPkBuffer, size_t *pqcPkLen,
    unsigned char **pqcMskBuffer, size_t *pqcMskLen,
    CPABEScheme scheme)
{
    int abeRes = hybrid_cpabe_setupBuffer_with_scheme(abePkBuffer, abePkLen, abeMskBuffer, abeMskLen, scheme);
    if (abeRes != HCPABE_SUCCESS) return abeRes;

    unsigned char *pqc_pub = nullptr, *pqc_priv = nullptr;
    size_t pqc_pub_len = 0, pqc_priv_len = 0;
    
    try
    {
        if (ml_dsa_87_generate_keypair(&pqc_pub, &pqc_pub_len, &pqc_priv, &pqc_priv_len) != HCPABE_SUCCESS) {
            throw std::runtime_error("Failed to generate PQC keypair.");
        }

        std::string pqcPubBase64, pqcSecBase64;
        CryptoPP::StringSource(pqc_pub, pqc_pub_len, true, new CryptoPP::Base64Encoder(new CryptoPP::StringSink(pqcPubBase64), false));
        CryptoPP::StringSource(pqc_priv, pqc_priv_len, true, new CryptoPP::Base64Encoder(new CryptoPP::StringSink(pqcSecBase64), false));

        *pqcPkLen = pqcPubBase64.size();
        *pqcPkBuffer = (unsigned char *)malloc(*pqcPkLen);
        if (!*pqcPkBuffer) throw std::bad_alloc();
        std::memcpy(*pqcPkBuffer, pqcPubBase64.data(), *pqcPkLen);

        *pqcMskLen = pqcSecBase64.size();
        *pqcMskBuffer = (unsigned char *)malloc(*pqcMskLen);
        if (!*pqcMskBuffer) throw std::bad_alloc();
        std::memcpy(*pqcMskBuffer, pqcSecBase64.data(), *pqcMskLen);

        if (pqc_pub) free(pqc_pub);
        if (pqc_priv) free(pqc_priv);

        return HCPABE_SUCCESS;
    }
    catch (...) { 
        if (pqc_pub) free(pqc_pub);
        if (pqc_priv) free(pqc_priv);
        return HCPABE_ERR_CRYPTO_FAILED; 
    }
}

int hybrid_cpabe_encryptBuffer_and_sign_with_scheme(
    const unsigned char *publicKey, size_t pkLen,
    const unsigned char *pqcPrivKey, size_t pqcPrivLen,
    const unsigned char *plaintext, size_t ptLen,
    const char *policy,
    unsigned char **ciphertext, size_t *ctLen,
    CPABEScheme scheme)
{
    std::string pqcPrivBase64(reinterpret_cast<const char*>(pqcPrivKey), pqcPrivLen);
    std::string pqcPrivRaw;
    CryptoPP::StringSource(pqcPrivBase64, true, new CryptoPP::Base64Decoder(new CryptoPP::StringSink(pqcPrivRaw)));

    uint32_t pol_len_32 = static_cast<uint32_t>(strlen(policy));
    std::vector<uint8_t> dataToSign;
    dataToSign.reserve(4 + pol_len_32 + ptLen);
    uint8_t* plen_ptr = reinterpret_cast<uint8_t*>(&pol_len_32);
    dataToSign.insert(dataToSign.end(), plen_ptr, plen_ptr + 4);
    dataToSign.insert(dataToSign.end(), reinterpret_cast<const uint8_t*>(policy), reinterpret_cast<const uint8_t*>(policy) + pol_len_32);
    dataToSign.insert(dataToSign.end(), plaintext, plaintext + ptLen);

    unsigned char *signature = nullptr;
    size_t sig_len = 0;
    if (ml_dsa_87_sign(dataToSign.data(), dataToSign.size(), (const unsigned char*)pqcPrivRaw.data(), &signature, &sig_len) != HCPABE_SUCCESS) {
        return HCPABE_ERR_CRYPTO_FAILED;
    }

    uint32_t sig_len_32 = static_cast<uint32_t>(sig_len);
    std::vector<uint8_t> payload;
    payload.reserve(4 + sig_len + dataToSign.size());
    uint8_t* slen_ptr = reinterpret_cast<uint8_t*>(&sig_len_32);
    payload.insert(payload.end(), slen_ptr, slen_ptr + 4);
    payload.insert(payload.end(), signature, signature + sig_len);
    payload.insert(payload.end(), dataToSign.begin(), dataToSign.end());

    int res = hybrid_cpabe_encryptBuffer_with_scheme(publicKey, pkLen, payload.data(), payload.size(), policy, ciphertext, ctLen, scheme);
    if (res != HCPABE_SUCCESS) {
        std::cout << "DEBUG: hybrid_cpabe_encryptBuffer_with_scheme returned " << res << std::endl;
    }
    
    secureWipe(&pqcPrivRaw[0], pqcPrivRaw.size());
    secureWipe(payload.data(), payload.size());
    if (signature) free(signature);
    return res;
}

int hybrid_cpabe_encryptBuffer_and_sign(
    const unsigned char *publicKey, size_t pkLen,
    const unsigned char *pqcPrivKey, size_t pqcPrivLen,
    const unsigned char *plaintext, size_t ptLen,
    const char *policy,
    unsigned char **ciphertext, size_t *ctLen)
{
    return hybrid_cpabe_encryptBuffer_and_sign_with_scheme(publicKey, pkLen, pqcPrivKey, pqcPrivLen, plaintext, ptLen, policy, ciphertext, ctLen, CPABE_SCHEME_AC17);
}

int hybrid_cpabe_encrypt_and_sign_with_scheme(const char *publicKeyFile, const char *pqcPrivateKeyFile, const char *plaintextFile, const char *policy, const char *ciphertextFile, CPABEScheme scheme)
{
    std::string pkData, pqcSkData, plaintext;
    if (!LoadFile(publicKeyFile, pkData, "Base64") || !LoadFile(pqcPrivateKeyFile, pqcSkData, "Base64")) return HCPABE_ERR_FILE_NOT_FOUND;

    std::ifstream ptF(plaintextFile, std::ios::binary);
    if (!ptF) return HCPABE_ERR_FILE_NOT_FOUND;
    plaintext.assign((std::istreambuf_iterator<char>(ptF)), std::istreambuf_iterator<char>());

    unsigned char *ct = nullptr;
    size_t ctLen = 0;
    int res = hybrid_cpabe_encryptBuffer_and_sign_with_scheme(
        (const unsigned char*)pkData.data(), pkData.size(),
        (const unsigned char*)pqcSkData.data(), pqcSkData.size(),
        (const unsigned char*)plaintext.data(), plaintext.size(),
        policy, &ct, &ctLen, scheme);
    
    if (res != HCPABE_SUCCESS) return res;

    try {
        CryptoPP::FileSink fileSink(ciphertextFile, true);
        fileSink.Put(ct, ctLen);
        fileSink.MessageEnd();
    } catch (...) {
        freeBuffer(ct);
        return HCPABE_ERR_FILE_NOT_FOUND;
    }
    freeBuffer(ct);
    std::cout << "Encrypt & Sign successful!" << std::endl;
    return HCPABE_SUCCESS;
}

int hybrid_cpabe_encrypt_and_sign(const char *publicKeyFile, const char *pqcPrivateKeyFile, const char *plaintextFile, const char *policy, const char *ciphertextFile)
{
    return hybrid_cpabe_encrypt_and_sign_with_scheme(publicKeyFile, pqcPrivateKeyFile, plaintextFile, policy, ciphertextFile, CPABE_SCHEME_AC17);
}

int hybrid_cpabe_decryptBuffer_and_verify(
    const unsigned char *privateKey, size_t skLen,
    const unsigned char *pqcPubKey, size_t pqcPubLen,
    const unsigned char *ciphertext, size_t ctLen,
    unsigned char **plaintext, size_t *ptLen)
{
    unsigned char *payload = nullptr;
    size_t payloadLen = 0;
    // Automatically detect scheme from ciphertext (in hybrid_cpabe_decryptBuffer)
    int res = hybrid_cpabe_decryptBuffer(privateKey, skLen, ciphertext, ctLen, &payload, &payloadLen);
    if (res != HCPABE_SUCCESS) return res;

    std::string pqcPubBase64(reinterpret_cast<const char*>(pqcPubKey), pqcPubLen);
    std::string pqcPubRaw;
    CryptoPP::StringSource(pqcPubBase64, true, new CryptoPP::Base64Decoder(new CryptoPP::StringSink(pqcPubRaw)));

    if (payloadLen < 4) {
        freeBuffer(payload);
        return HCPABE_ERR_CRYPTO_FAILED;
    }
    uint32_t sig_len_32 = 0;
    std::memcpy(&sig_len_32, payload, 4);
    if (payloadLen < 4 + sig_len_32) {
        freeBuffer(payload);
        return HCPABE_ERR_CRYPTO_FAILED;
    }

    const uint8_t *signature = payload + 4;
    const uint8_t *dataToSign = payload + 4 + sig_len_32;
    size_t dataToSignLen = payloadLen - 4 - sig_len_32;

    if (ml_dsa_87_verify(dataToSign, dataToSignLen, signature, sig_len_32, (const unsigned char*)pqcPubRaw.data()) != HCPABE_SUCCESS) {
        secureWipe(payload, payloadLen);
        freeBuffer(payload);
        return HCPABE_ERR_SIGNATURE_INVALID;
    }

    if (dataToSignLen < 4) {
        secureWipe(payload, payloadLen);
        freeBuffer(payload);
        return HCPABE_ERR_CRYPTO_FAILED;
    }
    uint32_t pol_len_32 = 0;
    std::memcpy(&pol_len_32, dataToSign, 4);

    if (dataToSignLen < 4 + pol_len_32) {
        secureWipe(payload, payloadLen);
        freeBuffer(payload);
        return HCPABE_ERR_CRYPTO_FAILED;
    }

    const uint8_t *original_pt = dataToSign + 4 + pol_len_32;
    size_t original_pt_len = dataToSignLen - 4 - pol_len_32;

    *ptLen = original_pt_len;
    *plaintext = (unsigned char *)malloc(*ptLen);
    if (!*plaintext) {
        secureWipe(payload, payloadLen);
        freeBuffer(payload);
        return HCPABE_ERR_MEMORY;
    }
    std::memcpy(*plaintext, original_pt, *ptLen);

    secureWipe(payload, payloadLen);
    freeBuffer(payload);
    return HCPABE_SUCCESS;
}

int hybrid_cpabe_decrypt_and_verify(const char *privateKeyFile, const char *pqcPublicKeyFile, const char *ciphertextFile, const char *recovertextFile)
{
    std::string skData, pqcPkData, ciphertext;
    if (!LoadFile(privateKeyFile, skData, "Base64") || !LoadFile(pqcPublicKeyFile, pqcPkData, "Base64")) return HCPABE_ERR_FILE_NOT_FOUND;

    std::ifstream ctF(ciphertextFile, std::ios::binary);
    if (!ctF) return HCPABE_ERR_FILE_NOT_FOUND;
    ciphertext.assign((std::istreambuf_iterator<char>(ctF)), std::istreambuf_iterator<char>());

    unsigned char *pt = nullptr;
    size_t ptLen = 0;
    // Decrypt detects scheme automatically
    int res = hybrid_cpabe_decryptBuffer_and_verify(
        (const unsigned char*)skData.data(), skData.size(),
        (const unsigned char*)pqcPkData.data(), pqcPkData.size(),
        (const unsigned char*)ciphertext.data(), ciphertext.size(),
        &pt, &ptLen);
    
    if (res != HCPABE_SUCCESS) return res;

    try {
        CryptoPP::FileSink fileSink(recovertextFile, true);
        fileSink.Put(pt, ptLen);
        fileSink.MessageEnd();
    } catch (...) {
        freeBuffer(pt);
        return HCPABE_ERR_FILE_NOT_FOUND;
    }
    freeBuffer(pt);
    std::cout << "Decrypt & Verify successful!" << std::endl;
    return HCPABE_SUCCESS;
}
