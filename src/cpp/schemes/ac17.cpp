/**
 * @file ac17.cpp
 * @brief AC17 CP-ABE scheme implementation using rabe FFI (Rust)
 * 
 * Provides CP-ABE operations for the AC17 scheme:
 * Setup, KeyGen, Encrypt, Decrypt, Load keys
 */

#include "hybrid_pq_cp_abe/cpabe-scheme.h"
#include "hybrid_pq_cp_abe/hybrid-pq-cp-abe.h"
#include "hybrid_pq_cp_abe/common-utils.h"
#include "rabe/rabe.h"

#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <algorithm>
#include <cstring>

// ============================================================================
// Internal Helpers
// ============================================================================

// Split attribute string into a vector (separated by space)
static std::vector<std::string> splitAttributes(const std::string &input)
{
    std::vector<std::string> result;
    std::istringstream ss(input);
    std::string item;
    while (std::getline(ss, item, ' '))
    {
        if (!item.empty())
            result.push_back(item);
    }
    return result;
}

// Normalize policy to JSON format for rabe AC17
static std::string ensureJsonString(const std::string &input)
{
    std::string lowerInput = toLowerCase(input);
    std::istringstream iss(lowerInput);
    std::string token;
    std::vector<std::string> tokens;
    std::string output;
    while (iss >> token)
    {
        size_t start = 0, end = 0;
        while (end < token.size())
        {
            if (token[end] == '(' || token[end] == ')')
            {
                if (start != end)
                {
                    tokens.push_back("\"" + token.substr(start, end - start) + "\"");
                }
                tokens.push_back(std::string(1, token[end]));
                start = end + 1;
            }
            end++;
        }
        if (start != end)
        {
            tokens.push_back("\"" + token.substr(start, end - start) + "\"");
        }
    }
    for (const auto &t : tokens)
    {
        output += t + " ";
    }
    if (!output.empty() && output.back() == ' ')
    {
        output.pop_back();
    }
    return output;
}

// ============================================================================
// AC17 Setup
// ============================================================================

int ac17_setup(const char *path)
{
    std::string strPath(path);
    std::string strFileFormat = HybridCPABE::DEFAULT_KEY_FORMAT;
    try
    {
        Ac17SetupResult setupResult = rabe_ac17_init();
        char *masterKeyJson = rabe_ac17_master_key_to_json(setupResult.master_key);
        char *publicKeyJson = rabe_ac17_public_key_to_json(setupResult.public_key);
        if (!masterKeyJson || !publicKeyJson)
        {
            throw std::runtime_error("Failed to convert master key or public key to JSON.");
        }

        std::string mskPath, pkPath;
        struct stat info;
        if (stat(strPath.c_str(), &info) == 0 && (info.st_mode & S_IFDIR)) {
            mskPath = strPath + "/cpabe_msk.key";
            pkPath = strPath + "/cpabe_pk.key";
        } else if (strPath.empty() || strPath.back() == '/' || strPath.back() == '\\') {
            mskPath = strPath + "cpabe_msk.key";
            pkPath = strPath + "cpabe_pk.key";
        } else {
            mskPath = strPath + "_msk.key";
            pkPath = strPath + "_pk.key";
        }

        if (strFileFormat == "JsonText" || strFileFormat == "HEX" || strFileFormat == "Base64")
        {
            bool masterKeySaved = SaveFile(mskPath, masterKeyJson, strFileFormat);
            bool publicKeySaved = SaveFile(pkPath, publicKeyJson, strFileFormat);
            
            rabe_free_json(masterKeyJson);
            rabe_free_json(publicKeyJson);
            rabe_ac17_free_master_key(setupResult.master_key);
            rabe_ac17_free_public_key(setupResult.public_key);
            
            if (!masterKeySaved || !publicKeySaved)
            {
                std::cerr << "AC17 Setup failed: Could not save key files." << std::endl;
                return HCPABE_ERR_FILE_NOT_FOUND;
            }
            
            std::cout << "AC17 Setup completed successfully." << std::endl;
            return HCPABE_SUCCESS;
        }
        else
        {
            throw std::invalid_argument("Unsupported key format.");
        }
    }
    catch (const std::exception &ex)
    {
        std::cerr << "AC17 Setup failed: " << ex.what() << std::endl;
        return HCPABE_ERR_CRYPTO_FAILED;
    }
}

int ac17_setupBuffer(unsigned char **pkBuffer, size_t *pkLen, unsigned char **mskBuffer, size_t *mskLen)
{
    try
    {
        Ac17SetupResult setupResult = rabe_ac17_init();
        char *masterKeyJson = rabe_ac17_master_key_to_json(setupResult.master_key);
        char *publicKeyJson = rabe_ac17_public_key_to_json(setupResult.public_key);
        if (!masterKeyJson || !publicKeyJson)
        {
            return HCPABE_ERR_CRYPTO_FAILED;
        }

        std::string pkBase64 = encodeBase64(reinterpret_cast<const unsigned char*>(publicKeyJson), std::strlen(publicKeyJson));
        std::string mskBase64 = encodeBase64(reinterpret_cast<const unsigned char*>(masterKeyJson), std::strlen(masterKeyJson));

        *pkLen = pkBase64.size();
        *pkBuffer = (unsigned char *)malloc(*pkLen);
        if (!*pkBuffer) return HCPABE_ERR_MEMORY;
        std::memcpy(*pkBuffer, pkBase64.data(), *pkLen);

        *mskLen = mskBase64.size();
        *mskBuffer = (unsigned char *)malloc(*mskLen);
        if (!*mskBuffer) return HCPABE_ERR_MEMORY;
        std::memcpy(*mskBuffer, mskBase64.data(), *mskLen);

        rabe_free_json(masterKeyJson);
        rabe_free_json(publicKeyJson);
        rabe_ac17_free_master_key(setupResult.master_key);
        rabe_ac17_free_public_key(setupResult.public_key);
        
        return HCPABE_SUCCESS;
    }
    catch (...)
    {
        return HCPABE_ERR_CRYPTO_FAILED;
    }
}

// ============================================================================
// AC17 KeyGen
// ============================================================================

int ac17_genkeyBuffer(const unsigned char *mskBuffer, size_t mskLen, const char *attrs, unsigned char **skBuffer, size_t *skLen)
{
    try
    {
        std::string mskStr(reinterpret_cast<const char*>(mskBuffer), mskLen);
        std::string mskDecoded = decodeBase64(mskStr);

        const void *masterKey = rabe_ac17_master_key_from_json(mskDecoded.c_str());
        if (!masterKey) return HCPABE_ERR_INVALID_KEY;

        std::string lowerAttributes = toLowerCase(attrs);
        std::vector<std::string> attrVec = splitAttributes(lowerAttributes);
        std::vector<const char *> attrList;
        for (const auto &attr : attrVec)
        {
            attrList.push_back(attr.c_str());
        }

        const void *secretKey = rabe_cp_ac17_generate_secret_key(masterKey, attrList.data(), attrList.size());
        rabe_ac17_free_master_key(masterKey);
        if (!secretKey) return HCPABE_ERR_CRYPTO_FAILED;

        char *secretKeyJson = rabe_cp_ac17_secret_key_to_json(secretKey);
        rabe_cp_ac17_free_secret_key(secretKey);
        if (!secretKeyJson) return HCPABE_ERR_CRYPTO_FAILED;

        std::string skBase64 = encodeBase64(reinterpret_cast<const unsigned char*>(secretKeyJson), std::strlen(secretKeyJson));
        
        *skLen = skBase64.size();
        *skBuffer = (unsigned char *)malloc(*skLen);
        if (!*skBuffer) return HCPABE_ERR_MEMORY;
        std::memcpy(*skBuffer, skBase64.data(), *skLen);

        secureWipe(secretKeyJson, std::strlen(secretKeyJson));
        rabe_free_json(secretKeyJson);
        
        return HCPABE_SUCCESS;
    }
    catch (...)
    {
        return HCPABE_ERR_CRYPTO_FAILED;
    }
}
int ac17_genkey(const char *mskFile, const char *attrs, const char *skFile)
{
    std::string strFileFormat = HybridCPABE::DEFAULT_KEY_FORMAT;
    try
    {
        std::string masterKeyData;
        if (!LoadFile(mskFile, masterKeyData, strFileFormat))
            return HCPABE_ERR_FILE_NOT_FOUND;

        const void *masterKey = rabe_ac17_master_key_from_json(masterKeyData.c_str());
        if (!masterKey)
            return HCPABE_ERR_INVALID_KEY;

        std::string lowerAttributes = toLowerCase(attrs);
        std::vector<std::string> attrVec = splitAttributes(lowerAttributes);
        std::vector<const char *> attrList;
        for (const auto &attr : attrVec)
        {
            attrList.push_back(attr.c_str());
        }

        const void *secretKey = rabe_cp_ac17_generate_secret_key(masterKey, attrList.data(), attrList.size());
        rabe_ac17_free_master_key(masterKey);
        if (!secretKey)
            return HCPABE_ERR_CRYPTO_FAILED;

        char *secretKeyJson = rabe_cp_ac17_secret_key_to_json(secretKey);
        rabe_cp_ac17_free_secret_key(secretKey);
        if (!secretKeyJson)
            return HCPABE_ERR_CRYPTO_FAILED;

        if (strFileFormat == "JsonText" || strFileFormat == "HEX" || strFileFormat == "Base64")
        {
            bool saved = SaveFile(skFile, secretKeyJson, strFileFormat);
            secureWipe(secretKeyJson, std::strlen(secretKeyJson));
            rabe_free_json(secretKeyJson);
            
            if (!saved)
            {
                std::cerr << "AC17: Failed to save private key file." << std::endl;
                return HCPABE_ERR_FILE_NOT_FOUND;
            }
            
            std::cout << "AC17: Private key generated successfully." << std::endl;
            return HCPABE_SUCCESS;
        }
        else
        {
            rabe_free_json(secretKeyJson);
            return HCPABE_ERR_UNSUPPORTED_FORMAT;
        }
    }
    catch (const std::exception &ex)
    {
        std::cerr << "AC17 KeyGen error: " << ex.what() << std::endl;
        return HCPABE_ERR_CRYPTO_FAILED;
    }
}

// ============================================================================
// AC17 Encapsulate Key
// ============================================================================

int ac17_encapsulate_key(
    const unsigned char *pkData, size_t pkLen,
    const char *policy,
    const unsigned char *plaintext, size_t ptLen,
    unsigned char **ciphertext, size_t *ctLen)
{
    try
    {
        // pkData is a JSON string of bytes
        std::string pkJson(reinterpret_cast<const char *>(pkData), pkLen);
        const void *publicKey = rabe_ac17_public_key_from_json(pkJson.c_str());
        if (!publicKey)
            return HCPABE_ERR_INVALID_KEY;

        std::string jsonPolicy = ensureJsonString(policy);
        const void *encKey = rabe_cp_ac17_encrypt(publicKey, jsonPolicy.c_str(),
                                                   reinterpret_cast<const char *>(plaintext), ptLen);
        rabe_ac17_free_public_key(publicKey);
        if (!encKey)
            return HCPABE_ERR_CRYPTO_FAILED;

        char *cipherJson = rabe_cp_ac17_cipher_to_json(encKey);
        rabe_cp_ac17_free_cipher(encKey);
        if (!cipherJson)
            return HCPABE_ERR_CRYPTO_FAILED;

        size_t jsonLen = std::strlen(cipherJson);
        *ctLen = jsonLen;
        *ciphertext = (unsigned char *)malloc(jsonLen);
        if (!*ciphertext)
        {
            rabe_free_json(cipherJson);
            return HCPABE_ERR_MEMORY;
        }
        std::memcpy(*ciphertext, cipherJson, jsonLen);
        rabe_free_json(cipherJson);

        return HCPABE_SUCCESS;
    }
    catch (const std::exception &ex)
    {
        std::cerr << "AC17 encrypt ABE key error: " << ex.what() << std::endl;
        return HCPABE_ERR_CRYPTO_FAILED;
    }
}

// ============================================================================
// AC17 Decapsulate Key
// ============================================================================

int ac17_decapsulate_key(
    const unsigned char *skData, size_t skLen,
    const unsigned char *ciphertext, size_t ctLen,
    unsigned char **plaintext, size_t *ptLen)
{
    try
    {
        std::string skJson(reinterpret_cast<const char *>(skData), skLen);
        std::string ctJson(reinterpret_cast<const char *>(ciphertext), ctLen);

        const void *secretKey = rabe_cp_ac17_secret_key_from_json(skJson.c_str());
        if (!secretKey)
            return HCPABE_ERR_INVALID_KEY;

        const void *cipherObj = rabe_cp_ac17_cipher_from_json(ctJson.c_str());
        if (!cipherObj)
        {
            rabe_cp_ac17_free_secret_key(secretKey);
            return HCPABE_ERR_CRYPTO_FAILED;
        }

        CBoxedBuffer result = rabe_cp_ac17_decrypt(cipherObj, secretKey);
        rabe_cp_ac17_free_secret_key(secretKey);
        rabe_cp_ac17_free_cipher(cipherObj);

        if (!result.buffer)
        {
            const char *error = rabe_get_thread_last_error();
            std::cerr << "AC17 Decryption failed: " << (error ? error : "Unknown error") << std::endl;
            return HCPABE_ERR_POLICY_MISMATCH;
        }

        *ptLen = result.len;
        *plaintext = (unsigned char *)malloc(result.len);
        if (!*plaintext)
        {
            rabe_free_boxed_buffer(result);
            return HCPABE_ERR_MEMORY;
        }
        std::memcpy(*plaintext, result.buffer, result.len);
        rabe_free_boxed_buffer(result);

        return HCPABE_SUCCESS;
    }
    catch (const std::exception &ex)
    {
        std::cerr << "AC17 decrypt ABE key error: " << ex.what() << std::endl;
        return HCPABE_ERR_CRYPTO_FAILED;
    }
}

// ============================================================================
// AC17 Load Keys
// ============================================================================

int ac17_load_pk(const char *file, unsigned char **pkData, size_t *pkLen)
{
    try
    {
        std::string data;
        if (!LoadFile(file, data, HybridCPABE::DEFAULT_KEY_FORMAT))
            return HCPABE_ERR_FILE_NOT_FOUND;

        *pkLen = data.size();
        *pkData = (unsigned char *)malloc(data.size());
        if (!*pkData)
            return HCPABE_ERR_MEMORY;
        std::memcpy(*pkData, data.data(), data.size());
        return HCPABE_SUCCESS;
    }
    catch (const std::exception &ex)
    {
        std::cerr << "AC17 load PK error: " << ex.what() << std::endl;
        return HCPABE_ERR_FILE_NOT_FOUND;
    }
}

int ac17_load_sk(const char *file, unsigned char **skData, size_t *skLen)
{
    try
    {
        std::string data;
        if (!LoadFile(file, data, HybridCPABE::DEFAULT_KEY_FORMAT))
            return HCPABE_ERR_FILE_NOT_FOUND;

        *skLen = data.size();
        *skData = (unsigned char *)malloc(data.size());
        if (!*skData)
            return HCPABE_ERR_MEMORY;
        std::memcpy(*skData, data.data(), data.size());
        return HCPABE_SUCCESS;
    }
    catch (const std::exception &ex)
    {
        std::cerr << "AC17 load SK error: " << ex.what() << std::endl;
        return HCPABE_ERR_FILE_NOT_FOUND;
    }
}

