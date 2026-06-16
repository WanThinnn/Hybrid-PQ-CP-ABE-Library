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
#include <iomanip>
#include <algorithm>
#include <cstring>

#include "rabe/rabe.h"
#include "hybrid_pq_cp_abe/hybrid-pq-cp-abe.h"

// Helper functions được chuyển sang common-utils.h
// Helper Functions
// ============================================================================

// Hàm splitAttributes: tách chuỗi thuộc tính thành vector
static std::vector<std::string> splitAttributes(const std::string &input)
{
    std::vector<std::string> result;
    std::istringstream ss(input);
    std::string item;
    while (std::getline(ss, item, ' '))
    {
        result.push_back(item);
    }
    return result;
}

// Hàm chuyển sang chữ thường
static std::string toLowerCase(const std::string &str) {
    std::string lowerStr = str;
    std::transform(lowerStr.begin(), lowerStr.end(), lowerStr.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return lowerStr;
}

// Hàm chuyển đổi dữ liệu thành vector<uint8_t>
static std::vector<uint8_t> convertToByteArray(const void *data, size_t length) {
    if (data == nullptr && length > 0) {
        throw std::invalid_argument("Null pointer with non-zero length!");
    }
    const uint8_t *bytePtr = static_cast<const uint8_t *>(data);
    return std::vector<uint8_t>(bytePtr, bytePtr + length);
}

// Hàm ensureJsonString - chuẩn hóa policy sang format JSON
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
// Core API Implementations
// ============================================================================

int setup(const char *path)
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
                std::cerr << "Setup failed: Could not save key files. Check if directory exists." << std::endl;
                return HCPABE_ERR_FILE_NOT_FOUND;
            }
            
            std::cout << "Setup completed successfully." << std::endl;
            return HCPABE_SUCCESS;
        }
        else
        {
            throw std::invalid_argument("Unsupported key format. Please choose 'JsonText', 'Base64', or 'HEX'.");
        }
    }
    catch (const std::exception &ex)
    {
        std::cerr << "Setup failed: " << ex.what() << std::endl;
        return HCPABE_ERR_CRYPTO_FAILED;
    }
}

int generateSecretKey(const char *masterKeyFile, const char *attributes, const char *privateKeyFile)
{
    std::string strFileFormat = HybridCPABE::DEFAULT_KEY_FORMAT;
    std::string masterKeyStr;
    try
    {
        std::string masterKeyData;
        if (!LoadFile(masterKeyFile, masterKeyData, strFileFormat))
            return HCPABE_ERR_FILE_NOT_FOUND;
        masterKeyStr = masterKeyData;
        const void *masterKey = rabe_ac17_master_key_from_json(masterKeyStr.c_str());
        if (!masterKey)
            return HCPABE_ERR_INVALID_KEY;
        std::string lowerAttributes = toLowerCase(attributes);
        std::vector<std::string> attrVec = splitAttributes(lowerAttributes);
        std::vector<const char *> attrList;
        for (const auto &attr : attrVec)
        {
            attrList.push_back(attr.c_str());
        }
        const void *secretKey = rabe_cp_ac17_generate_secret_key(masterKey, attrList.data(), attrList.size());
        if (!secretKey)
            return HCPABE_ERR_CRYPTO_FAILED;
        char *secretKeyJson = rabe_cp_ac17_secret_key_to_json(secretKey);
        if (!secretKeyJson)
        {
            rabe_cp_ac17_free_secret_key(secretKey);
            return HCPABE_ERR_CRYPTO_FAILED;
        }
        if (strFileFormat == "JsonText" || strFileFormat == "HEX" || strFileFormat == "Base64")
        {
            bool saved = SaveFile(privateKeyFile, secretKeyJson, strFileFormat);
            
            // Giải phóng và xóa bộ nhớ nhạy cảm
            secureWipe(secretKeyJson, std::strlen(secretKeyJson));
            rabe_free_json(secretKeyJson);
            rabe_cp_ac17_free_secret_key(secretKey);
            
            if (!saved)
            {
                std::cerr << "Failed to save private key file. Check if directory exists." << std::endl;
                return HCPABE_ERR_FILE_NOT_FOUND;
            }
            
            std::cout << "Private key generated successfully." << std::endl;
            return HCPABE_SUCCESS;
        }
        else
        {
            rabe_free_json(secretKeyJson);
            rabe_cp_ac17_free_secret_key(secretKey);
            return HCPABE_ERR_UNSUPPORTED_FORMAT;
        }
        // Giải phóng và xóa bộ nhớ nhạy cảm
        secureWipe(secretKeyJson, std::strlen(secretKeyJson));
        rabe_free_json(secretKeyJson);
        rabe_cp_ac17_free_secret_key(secretKey);
        return HCPABE_SUCCESS;
    }
    catch (const std::exception &ex)
    {
        std::cerr << "Error generating private key: " << ex.what() << std::endl;
        return HCPABE_ERR_CRYPTO_FAILED;
    }
}

int hybrid_cpabe_encrypt(const char *publicKeyFile, const char *plaintextFile, const char *policy, const char *ciphertextFile)
{
    std::string aesKey;
    std::string randomKeyStr;
    
    try
    {
        std::string strPublicKeyFile(publicKeyFile);
        std::string strPlaintextFile(plaintextFile);
        std::string strCiphertextFile(ciphertextFile);

        CryptoPP::AutoSeededRandomPool prng;
        CryptoPP::Integer randomKey(prng, 12288);
        randomKey.Encode(CryptoPP::StringSink(randomKeyStr).Ref(), randomKey.MinEncodedSize());

        // Mã hóa randomKey bằng CP-ABE
        std::string publicKeyData;
        if (!LoadFile(strPublicKeyFile, publicKeyData, "Base64"))
            return HCPABE_ERR_FILE_NOT_FOUND;
        const void *publicKey = rabe_ac17_public_key_from_json(publicKeyData.c_str());
        if (!publicKey)
            return HCPABE_ERR_INVALID_KEY;
        
        std::string jsonPolicy = ensureJsonString(policy);
        const void *encryptedKey = rabe_cp_ac17_encrypt(publicKey, jsonPolicy.c_str(), randomKeyStr.c_str(), randomKeyStr.size());
        if (!encryptedKey)
        {
            rabe_ac17_free_public_key(publicKey);
            return HCPABE_ERR_CRYPTO_FAILED;
        }
        
        char *encryptedKeyJson = rabe_cp_ac17_cipher_to_json(encryptedKey);
        if (!encryptedKeyJson)
        {
            rabe_cp_ac17_free_cipher(encryptedKey);
            rabe_ac17_free_public_key(publicKey);
            return HCPABE_ERR_CRYPTO_FAILED;
        }
        std::string encryptedKeyB = encryptedKeyJson;
        rabe_cp_ac17_free_cipher(encryptedKey);
        rabe_ac17_free_public_key(publicKey);
        rabe_free_json(encryptedKeyJson);

        // Tạo khóa AES từ randomKey (hash bằng SHA3-256)
        CryptoPP::SHA3_256 hash;
        aesKey.resize(hash.DigestSize(), 0);
        hash.Update(reinterpret_cast<const CryptoPP::byte *>(randomKeyStr.data()), randomKeyStr.size());
        hash.Final(reinterpret_cast<CryptoPP::byte *>(&aesKey[0]));

        // Đọc plaintext từ file
        std::ifstream file(strPlaintextFile, std::ios::binary);
        if (!file)
            return HCPABE_ERR_FILE_NOT_FOUND;
        std::string plaintext((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        file.close();

        // Chuẩn bị AAD: Version + IV + lenEncryptedKey + encryptedKeyB
        CryptoPP::byte iv[HybridCPABE::GCM_IV_SIZE];
        prng.GenerateBlock(iv, sizeof(iv));

        std::string aad;
        aad.push_back(static_cast<char>(HybridCPABE::FORMAT_VERSION));
        aad.append(reinterpret_cast<const char *>(iv), sizeof(iv));
        uint64_t lenEncryptedKey = encryptedKeyB.size();
        aad.append(reinterpret_cast<const char *>(&lenEncryptedKey), sizeof(lenEncryptedKey));
        aad.append(encryptedKeyB);

        unsigned char *aesCiphertext = nullptr;
        size_t aesCtLen = 0;
        int aesRes = aes_gcm_encrypt(
            reinterpret_cast<const unsigned char*>(aesKey.data()), aesKey.size(),
            iv, sizeof(iv),
            reinterpret_cast<const unsigned char*>(plaintext.data()), plaintext.size(),
            reinterpret_cast<const unsigned char*>(aad.data()), aad.size(),
            &aesCiphertext, &aesCtLen
        );

        if (aesRes != HCPABE_SUCCESS) {
            secureWipe(&aesKey[0], aesKey.size());
            secureWipe(&randomKeyStr[0], randomKeyStr.size());
            return aesRes;
        }

        // Ghép nối: AAD + ciphertext
        std::string combined;
        combined.append(aad);
        combined.append(reinterpret_cast<const char*>(aesCiphertext), aesCtLen);
        free(aesCiphertext);

        // Lưu trực tiếp dưới dạng binary
        try {
            CryptoPP::FileSink fileSink(strCiphertextFile.c_str(), true);
            fileSink.Put(reinterpret_cast<const CryptoPP::byte *>(combined.data()), combined.size());
            fileSink.MessageEnd();
        }
        catch (const CryptoPP::Exception &ex)
        {
            std::cerr << "Failed to save ciphertext file: " << ex.what() << std::endl;
            secureWipe(&aesKey[0], aesKey.size());
            secureWipe(&randomKeyStr[0], randomKeyStr.size());
            return HCPABE_ERR_FILE_NOT_FOUND;
        }
        
        std::cout << "Encryption successful!" << std::endl;
        
        // Xóa bộ nhớ nhạy cảm
        secureWipe(&aesKey[0], aesKey.size());
        secureWipe(&randomKeyStr[0], randomKeyStr.size());
        
        return HCPABE_SUCCESS;
    }
    catch (const CryptoPP::Exception &ex)
    {
        std::cerr << "Crypto++ exception: " << ex.what() << std::endl;
        secureWipe(&aesKey[0], aesKey.size());
        secureWipe(&randomKeyStr[0], randomKeyStr.size());
        return HCPABE_ERR_CRYPTO_FAILED;
    }
    catch (const std::exception &ex)
    {
        std::cerr << "Standard exception: " << ex.what() << std::endl;
        secureWipe(&aesKey[0], aesKey.size());
        secureWipe(&randomKeyStr[0], randomKeyStr.size());
        return HCPABE_ERR_CRYPTO_FAILED;
    }
}

int hybrid_cpabe_decrypt(const char *privateKeyFile, const char *ciphertextFile, const char *recovertextFile)
{
    std::string aesKey;
    std::string recoveredKeyStr;
    
    try
    {
        std::string strCiphertextFile(ciphertextFile);
        
        // Đọc trực tiếp dữ liệu binary từ file
        std::string decodedCiphertext;
        try {
            CryptoPP::FileSource fileSource(strCiphertextFile.c_str(), true, new CryptoPP::StringSink(decodedCiphertext));
        }
        catch (const CryptoPP::Exception &ex)
        {
            std::cerr << "Failed to read ciphertext file: " << ex.what() << std::endl;
            return HCPABE_ERR_FILE_NOT_FOUND;
        }

        // Kiểm tra version byte
        if (decodedCiphertext.empty())
            return HCPABE_ERR_CRYPTO_FAILED;
            
        uint8_t version = static_cast<uint8_t>(decodedCiphertext[0]);
        if (version != HybridCPABE::FORMAT_VERSION)
        {
            std::cerr << "Unsupported ciphertext format version: " << static_cast<int>(version) << std::endl;
            return HCPABE_ERR_VERSION_MISMATCH;
        }
        
        uint64_t offset = 1;  // Skip version byte

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
        std::string ciphertext = decodedCiphertext.substr(offset);

        // Tải private key
        std::string secretKeyData;
        if (!LoadFile(privateKeyFile, secretKeyData, "Base64"))
            return HCPABE_ERR_FILE_NOT_FOUND;
        const void *secretKey = rabe_cp_ac17_secret_key_from_json(secretKeyData.c_str());
        if (!secretKey)
            return HCPABE_ERR_INVALID_KEY;

        // Giải mã khóa ngẫu nhiên bằng CP-ABE
        const void *encryptedKey = rabe_cp_ac17_cipher_from_json(encryptedKeyB.c_str());
        if (!encryptedKey)
        {
            rabe_cp_ac17_free_secret_key(secretKey);
            return HCPABE_ERR_CRYPTO_FAILED;
        }
        CBoxedBuffer recoveredKey = rabe_cp_ac17_decrypt(encryptedKey, secretKey);
        if (!recoveredKey.buffer)
        {
            const char *error = rabe_get_thread_last_error();
            std::cerr << "CP-ABE Decryption failed: " << (error ? error : "Unknown error") << std::endl;
            rabe_cp_ac17_free_secret_key(secretKey);
            rabe_cp_ac17_free_cipher(encryptedKey);
            return HCPABE_ERR_POLICY_MISMATCH;
        }
        
        CryptoPP::Integer recoveredRandomKey(reinterpret_cast<const CryptoPP::byte *>(recoveredKey.buffer), recoveredKey.len);
        rabe_free_boxed_buffer(recoveredKey);
        CryptoPP::SHA3_256 hash;
        aesKey.resize(hash.DigestSize(), 0);
        recoveredRandomKey.Encode(CryptoPP::StringSink(recoveredKeyStr).Ref(), recoveredRandomKey.MinEncodedSize());
        hash.Update(reinterpret_cast<const CryptoPP::byte *>(recoveredKeyStr.data()), recoveredKeyStr.size());
        hash.Final(reinterpret_cast<CryptoPP::byte *>(&aesKey[0]));

        // Chuẩn bị AAD
        std::string aad = decodedCiphertext.substr(0, offset);

        unsigned char *recoveredPt = nullptr;
        size_t recoveredPtLen = 0;
        int decRes = aes_gcm_decrypt(
            reinterpret_cast<const unsigned char*>(aesKey.data()), aesKey.size(),
            iv, sizeof(iv),
            reinterpret_cast<const unsigned char*>(ciphertext.data()), ciphertext.size(),
            reinterpret_cast<const unsigned char*>(aad.data()), aad.size(),
            &recoveredPt, &recoveredPtLen
        );

        if (decRes != HCPABE_SUCCESS)
        {
            secureWipe(&aesKey[0], aesKey.size());
            secureWipe(&recoveredKeyStr[0], recoveredKeyStr.size());
            rabe_cp_ac17_free_secret_key(secretKey);
            rabe_cp_ac17_free_cipher(encryptedKey);
            return decRes;
        }
        std::string recovered(reinterpret_cast<const char*>(recoveredPt), recoveredPtLen);
        free(recoveredPt);

        // Lưu file đã giải mã
        try {
            CryptoPP::FileSink fileSink(recovertextFile);
            fileSink.Put(reinterpret_cast<const CryptoPP::byte *>(recovered.data()), recovered.size());
            fileSink.MessageEnd();
        }
        catch (const CryptoPP::Exception &ex)
        {
            std::cerr << "Failed to save decrypted file: " << ex.what() << std::endl;
            secureWipe(&aesKey[0], aesKey.size());
            secureWipe(&recoveredKeyStr[0], recoveredKeyStr.size());
            rabe_cp_ac17_free_secret_key(secretKey);
            rabe_cp_ac17_free_cipher(encryptedKey);
            return HCPABE_ERR_FILE_NOT_FOUND;
        }
        
        std::cout << "Decryption successful!" << std::endl;
        
        // Xóa bộ nhớ nhạy cảm và giải phóng
        secureWipe(&aesKey[0], aesKey.size());
        secureWipe(&recoveredKeyStr[0], recoveredKeyStr.size());
        rabe_cp_ac17_free_secret_key(secretKey);
        rabe_cp_ac17_free_cipher(encryptedKey);
        
        return HCPABE_SUCCESS;
    }
    catch (const CryptoPP::Exception &ex)
    {
        std::cerr << "Crypto++ exception: " << ex.what() << std::endl;
        secureWipe(&aesKey[0], aesKey.size());
        secureWipe(&recoveredKeyStr[0], recoveredKeyStr.size());
        return HCPABE_ERR_CRYPTO_FAILED;
    }
    catch (const std::exception &ex)
    {
        std::cerr << "Standard exception: " << ex.what() << std::endl;
        secureWipe(&aesKey[0], aesKey.size());
        secureWipe(&recoveredKeyStr[0], recoveredKeyStr.size());
        return HCPABE_ERR_CRYPTO_FAILED;
    }
}

// ============================================================================
// Buffer-based API Implementations (Placeholder - cần implement đầy đủ)
// ============================================================================

int hybrid_cpabe_encryptBuffer(
    const unsigned char *publicKey, size_t pkLen,
    const unsigned char *plaintext, size_t ptLen,
    const char *policy,
    unsigned char **ciphertext, size_t *ctLen)
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

        // Parse public key from buffer (JSON string)
        std::string pkStr(reinterpret_cast<const char*>(publicKey), pkLen);
        const void *pkObj = rabe_ac17_public_key_from_json(pkStr.c_str());
        if (!pkObj)
            return HCPABE_ERR_INVALID_KEY;

        std::string jsonPolicy = ensureJsonString(policy);
        const void *encryptedKey = rabe_cp_ac17_encrypt(pkObj, jsonPolicy.c_str(), randomKeyStr.c_str(), randomKeyStr.size());
        if (!encryptedKey)
        {
            rabe_ac17_free_public_key(pkObj);
            return HCPABE_ERR_CRYPTO_FAILED;
        }
        
        char *encryptedKeyJson = rabe_cp_ac17_cipher_to_json(encryptedKey);
        if (!encryptedKeyJson)
        {
            rabe_cp_ac17_free_cipher(encryptedKey);
            rabe_ac17_free_public_key(pkObj);
            return HCPABE_ERR_CRYPTO_FAILED;
        }
        std::string encryptedKeyB = encryptedKeyJson;
        rabe_cp_ac17_free_cipher(encryptedKey);
        rabe_ac17_free_public_key(pkObj);
        rabe_free_json(encryptedKeyJson);

        // AES Key generation
        CryptoPP::SHA3_256 hash;
        aesKey.resize(hash.DigestSize(), 0);
        hash.Update(reinterpret_cast<const CryptoPP::byte *>(randomKeyStr.data()), randomKeyStr.size());
        hash.Final(reinterpret_cast<CryptoPP::byte *>(&aesKey[0]));

        // Chuẩn bị AAD: Version + IV + lenEncryptedKey + encryptedKeyB
        CryptoPP::byte iv[HybridCPABE::GCM_IV_SIZE];
        prng.GenerateBlock(iv, sizeof(iv));

        std::string aad;
        aad.push_back(static_cast<char>(HybridCPABE::FORMAT_VERSION));
        aad.append(reinterpret_cast<const char *>(iv), sizeof(iv));
        uint64_t lenEncryptedKey = encryptedKeyB.size();
        aad.append(reinterpret_cast<const char *>(&lenEncryptedKey), sizeof(lenEncryptedKey));
        aad.append(encryptedKeyB);

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
        free(aesCiphertext);

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
            
        // Check Version
        uint8_t version = static_cast<uint8_t>(decodedCiphertext[0]);
        if (version != HybridCPABE::FORMAT_VERSION)
            return HCPABE_ERR_VERSION_MISMATCH;
            
        uint64_t offset = 1;
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

        // Load private key (JSON string)
        std::string skStr(reinterpret_cast<const char*>(privateKey), skLen);
        const void *secretKey = rabe_cp_ac17_secret_key_from_json(skStr.c_str());
        if (!secretKey)
            return HCPABE_ERR_INVALID_KEY;

        const void *encryptedKeyObj = rabe_cp_ac17_cipher_from_json(encryptedKeyB.c_str());
        if (!encryptedKeyObj)
        {
            rabe_cp_ac17_free_secret_key(secretKey);
            return HCPABE_ERR_CRYPTO_FAILED;
        }
        
        CBoxedBuffer recoveredKey = rabe_cp_ac17_decrypt(encryptedKeyObj, secretKey);
        if (!recoveredKey.buffer)
        {
            rabe_cp_ac17_free_secret_key(secretKey);
            rabe_cp_ac17_free_cipher(encryptedKeyObj);
            return HCPABE_ERR_POLICY_MISMATCH;
        }
        
        CryptoPP::Integer recoveredRandomKey(reinterpret_cast<const CryptoPP::byte *>(recoveredKey.buffer), recoveredKey.len);
        rabe_free_boxed_buffer(recoveredKey);
        CryptoPP::SHA3_256 hash;
        aesKey.resize(hash.DigestSize(), 0);
        recoveredRandomKey.Encode(CryptoPP::StringSink(recoveredKeyStr).Ref(), recoveredRandomKey.MinEncodedSize());
        hash.Update(reinterpret_cast<const CryptoPP::byte *>(recoveredKeyStr.data()), recoveredKeyStr.size());
        hash.Final(reinterpret_cast<CryptoPP::byte *>(&aesKey[0]));

        // Chuẩn bị AAD
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
            rabe_cp_ac17_free_secret_key(secretKey);
            rabe_cp_ac17_free_cipher(encryptedKeyObj);
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
            rabe_cp_ac17_free_secret_key(secretKey);
            rabe_cp_ac17_free_cipher(encryptedKeyObj);
            return HCPABE_ERR_MEMORY;
        }
        std::memcpy(*plaintext, recovered.data(), *ptLen);

        secureWipe(&aesKey[0], aesKey.size());
        secureWipe(&recoveredKeyStr[0], recoveredKeyStr.size());
        rabe_cp_ac17_free_secret_key(secretKey);
        rabe_cp_ac17_free_cipher(encryptedKeyObj);
        
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
