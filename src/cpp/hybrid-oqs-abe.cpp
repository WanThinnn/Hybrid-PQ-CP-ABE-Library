#include "hybrid_pq_cp_abe/hybrid-pq-cp-abe.h"
#include "rabe/rabe.h"
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

// Helper functions được chuyển sang common-utils.h
int hybrid_cpabe_setup_with_pqc(const char *path)
{
    std::string strPath(path);
    std::string strFileFormat = HybridCPABE::DEFAULT_KEY_FORMAT;
    unsigned char *pqc_pub = nullptr, *pqc_priv = nullptr;
    size_t pqc_pub_len = 0, pqc_priv_len = 0;
    char *masterKeyJson = nullptr, *publicKeyJson = nullptr;
    Ac17SetupResult setupResult;
    
    try
    {
        setupResult = rabe_ac17_init();
        masterKeyJson = rabe_ac17_master_key_to_json(setupResult.master_key);
        publicKeyJson = rabe_ac17_public_key_to_json(setupResult.public_key);
        if (!masterKeyJson || !publicKeyJson)
            throw std::runtime_error("Failed to convert keys to JSON.");

        if (ml_dsa_87_generate_keypair(&pqc_pub, &pqc_pub_len, &pqc_priv, &pqc_priv_len) != HCPABE_SUCCESS) {
            throw std::runtime_error("Failed to generate PQC keypair.");
        }

        std::string pqcPubBase64, pqcSecBase64;
        CryptoPP::StringSource(pqc_pub, pqc_pub_len, true, new CryptoPP::Base64Encoder(new CryptoPP::StringSink(pqcPubBase64), false));
        CryptoPP::StringSource(pqc_priv, pqc_priv_len, true, new CryptoPP::Base64Encoder(new CryptoPP::StringSink(pqcSecBase64), false));

        std::string msKeyStr(masterKeyJson);
        std::string pbKeyStr(publicKeyJson);

        std::string mskPath, pkPath, pqcMskPath, pqcPkPath;
        struct stat info;
        if (stat(strPath.c_str(), &info) == 0 && (info.st_mode & S_IFDIR)) {
            mskPath = strPath + "/cpabe_msk.key";
            pkPath = strPath + "/cpabe_pk.key";
            pqcMskPath = strPath + "/pqc_sk.key";
            pqcPkPath = strPath + "/pqc_pk.key";
        } else if (strPath.empty() || strPath.back() == '/' || strPath.back() == '\\') {
            mskPath = strPath + "cpabe_msk.key";
            pkPath = strPath + "cpabe_pk.key";
            pqcMskPath = strPath + "pqc_sk.key";
            pqcPkPath = strPath + "pqc_pk.key";
        } else {
            mskPath = strPath + "_msk.key";
            pkPath = strPath + "_pk.key";
            pqcMskPath = strPath + "_pqc_sk.key";
            pqcPkPath = strPath + "_pqc_pk.key";
        }

        if (strFileFormat == "JsonText" || strFileFormat == "HEX" || strFileFormat == "Base64")
        {
            bool msSaved = SaveFile(mskPath, msKeyStr.c_str(), strFileFormat);
            bool pbSaved = SaveFile(pkPath, pbKeyStr.c_str(), strFileFormat);
            bool pqcMsSaved = SaveFile(pqcMskPath, pqcSecBase64.c_str(), strFileFormat);
            bool pqcPbSaved = SaveFile(pqcPkPath, pqcPubBase64.c_str(), strFileFormat);
            
            rabe_free_json(masterKeyJson);
            rabe_free_json(publicKeyJson);
            rabe_ac17_free_master_key(setupResult.master_key);
            rabe_ac17_free_public_key(setupResult.public_key);
            if (pqc_pub) free(pqc_pub);
            if (pqc_priv) free(pqc_priv);
            
            if (!msSaved || !pbSaved || !pqcMsSaved || !pqcPbSaved) return HCPABE_ERR_FILE_NOT_FOUND;
            
            std::cout << "Setup with PQC completed successfully." << std::endl;
            return HCPABE_SUCCESS;
        }
        else
        {
            throw std::invalid_argument("Unsupported format.");
        }
    }
    catch (...) { 
        if (masterKeyJson) rabe_free_json(masterKeyJson);
        if (publicKeyJson) rabe_free_json(publicKeyJson);
        rabe_ac17_free_master_key(setupResult.master_key);
        rabe_ac17_free_public_key(setupResult.public_key);
        if (pqc_pub) free(pqc_pub);
        if (pqc_priv) free(pqc_priv);
        return HCPABE_ERR_CRYPTO_FAILED; 
    }
}

int hybrid_cpabe_encryptBuffer_and_sign(
    const unsigned char *publicKey, size_t pkLen,
    const unsigned char *pqcPrivKey, size_t pqcPrivLen,
    const unsigned char *plaintext, size_t ptLen,
    const char *policy,
    unsigned char **ciphertext, size_t *ctLen)
{
    std::string pqcPrivBase64(reinterpret_cast<const char*>(pqcPrivKey), pqcPrivLen);
    std::string pqcPrivRaw;
    CryptoPP::StringSource(pqcPrivBase64, true, new CryptoPP::Base64Decoder(new CryptoPP::StringSink(pqcPrivRaw)));

    unsigned char *signature = nullptr;
    size_t sig_len = 0;
    if (ml_dsa_87_sign(plaintext, ptLen, (const unsigned char*)pqcPrivRaw.data(), &signature, &sig_len) != HCPABE_SUCCESS) {
        return HCPABE_ERR_CRYPTO_FAILED;
    }

    uint32_t sig_len_32 = static_cast<uint32_t>(sig_len);
    std::vector<uint8_t> payload;
    payload.reserve(4 + sig_len + ptLen);
    uint8_t* slen_ptr = reinterpret_cast<uint8_t*>(&sig_len_32);
    payload.insert(payload.end(), slen_ptr, slen_ptr + 4);
    payload.insert(payload.end(), signature, signature + sig_len);
    payload.insert(payload.end(), plaintext, plaintext + ptLen);

    std::string pkJson(reinterpret_cast<const char*>(publicKey), pkLen);
    int res = hybrid_cpabe_encryptBuffer((const unsigned char*)pkJson.data(), pkJson.size(), payload.data(), payload.size(), policy, ciphertext, ctLen);
    if (res != HCPABE_SUCCESS) {
        std::cout << "DEBUG: hybrid_cpabe_encryptBuffer returned " << res << std::endl;
    }
    
    secureWipe(&pqcPrivRaw[0], pqcPrivRaw.size());
    secureWipe(payload.data(), payload.size());
    if (signature) free(signature);
    return res;
}

int hybrid_cpabe_decryptBuffer_and_verify(
    const unsigned char *privateKey, size_t skLen,
    const unsigned char *pqcPubKey, size_t pqcPubLen,
    const unsigned char *ciphertext, size_t ctLen,
    unsigned char **plaintext, size_t *ptLen)
{
    unsigned char *payload = nullptr;
    size_t payloadLen = 0;
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
    const uint8_t *original_pt = payload + 4 + sig_len_32;
    size_t original_pt_len = payloadLen - 4 - sig_len_32;

    if (ml_dsa_87_verify(original_pt, original_pt_len, signature, sig_len_32, (const unsigned char*)pqcPubRaw.data()) != HCPABE_SUCCESS) {
        secureWipe(payload, payloadLen);
        freeBuffer(payload);
        return HCPABE_ERR_SIGNATURE_INVALID;
    }

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

int hybrid_cpabe_encrypt_and_sign(const char *publicKeyFile, const char *pqcPrivateKeyFile, const char *plaintextFile, const char *policy, const char *ciphertextFile)
{
    std::string pkData, pqcSkData, plaintext;
    if (!LoadFile(publicKeyFile, pkData, "Base64") || !LoadFile(pqcPrivateKeyFile, pqcSkData, "Base64")) return HCPABE_ERR_FILE_NOT_FOUND;

    std::ifstream ptF(plaintextFile, std::ios::binary);
    if (!ptF) return HCPABE_ERR_FILE_NOT_FOUND;
    plaintext.assign((std::istreambuf_iterator<char>(ptF)), std::istreambuf_iterator<char>());

    unsigned char *ct = nullptr;
    size_t ctLen = 0;
    int res = hybrid_cpabe_encryptBuffer_and_sign(
        (const unsigned char*)pkData.data(), pkData.size(),
        (const unsigned char*)pqcSkData.data(), pqcSkData.size(),
        (const unsigned char*)plaintext.data(), plaintext.size(),
        policy, &ct, &ctLen);
    
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

int hybrid_cpabe_decrypt_and_verify(const char *privateKeyFile, const char *pqcPublicKeyFile, const char *ciphertextFile, const char *recovertextFile)
{
    std::string skData, pqcPkData, ciphertext;
    if (!LoadFile(privateKeyFile, skData, "Base64") || !LoadFile(pqcPublicKeyFile, pqcPkData, "Base64")) return HCPABE_ERR_FILE_NOT_FOUND;

    std::ifstream ctF(ciphertextFile, std::ios::binary);
    if (!ctF) return HCPABE_ERR_FILE_NOT_FOUND;
    ciphertext.assign((std::istreambuf_iterator<char>(ctF)), std::istreambuf_iterator<char>());

    unsigned char *pt = nullptr;
    size_t ptLen = 0;
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
