#include "abe-internal.h"
#include <cryptopp/sha3.h>

int hybrid_cpabe_decryptBuffer_impl(const unsigned char *privateKey, size_t skLen, const unsigned char *ciphertext,
                                    size_t ctLen, unsigned char **plaintext, size_t *ptLen)
{
    if (!plaintext || !ptLen) return HCPABE_ERR_INVALID_PARAM;
    *plaintext = nullptr;
    *ptLen = 0;
    std::string aesKey;
    std::string recoveredKeyStr;

    try
    {
        if (!privateKey || !ciphertext || !plaintext || !ptLen)
            return HCPABE_ERR_INVALID_PARAM;

        std::string decodedCiphertext(reinterpret_cast<const char *>(ciphertext), ctLen);

        if (decodedCiphertext.empty())
            return HCPABE_ERR_CRYPTO_FAILED;

        uint8_t version = static_cast<uint8_t>(decodedCiphertext[0]);
        CPABEScheme scheme = CPABE_SCHEME_AC17;
        uint64_t offset = 1;

        if (version == HybridCPABE::FORMAT_VERSION_2)
        {
            // Version 2 has scheme byte
            if (decodedCiphertext.size() < offset + 1)
                return HCPABE_ERR_CRYPTO_FAILED;
            scheme = static_cast<CPABEScheme>(decodedCiphertext[1]);
            offset += 1;
        }
        else if (version == HybridCPABE::FORMAT_VERSION)
        {
            // Legacy version implies AC17
            scheme = CPABE_SCHEME_AC17;
        }
        else
        {
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

        if (lenEncryptedKey > decodedCiphertext.size() - offset)
            return HCPABE_ERR_CRYPTO_FAILED;
        std::string encryptedKeyB = decodedCiphertext.substr(offset, lenEncryptedKey);
        offset += lenEncryptedKey;
        std::string aesCiphertext = decodedCiphertext.substr(offset);

        // ABE Decrypt Random Key
        unsigned char *recoveredAbeKey = nullptr;
        size_t recoveredAbeKeyLen = 0;
        int abeRes = HCPABE_ERR_INVALID_PARAM;

        switch (scheme)
        {
        case CPABE_SCHEME_AC17:
            abeRes =
                ac17_decapsulate_key(privateKey, skLen, reinterpret_cast<const unsigned char *>(encryptedKeyB.data()),
                                     encryptedKeyB.size(), &recoveredAbeKey, &recoveredAbeKeyLen);
            break;
        case CPABE_SCHEME_TKN20:
            abeRes =
                tkn20_decapsulate_key(privateKey, skLen, reinterpret_cast<const unsigned char *>(encryptedKeyB.data()),
                                      encryptedKeyB.size(), &recoveredAbeKey, &recoveredAbeKeyLen);
            break;
        case CPABE_SCHEME_COVERCRYPT:
            abeRes = covercrypt_decapsulate_key(privateKey, skLen,
                                                reinterpret_cast<const unsigned char *>(encryptedKeyB.data()),
                                                encryptedKeyB.size(), &recoveredAbeKey, &recoveredAbeKeyLen);
            break;
        }

        if (abeRes != HCPABE_SUCCESS)
            return abeRes;

        // Extract and hash random key
        CryptoPP::Integer recoveredRandomKey(reinterpret_cast<const CryptoPP::byte *>(recoveredAbeKey),
                                             recoveredAbeKeyLen);
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
        int decRes = aes_gcm_decrypt(reinterpret_cast<const unsigned char *>(aesKey.data()), aesKey.size(), iv,
                                     sizeof(iv), reinterpret_cast<const unsigned char *>(aesCiphertext.data()),
                                     aesCiphertext.size(), reinterpret_cast<const unsigned char *>(aad.data()),
                                     aad.size(), &recoveredPt, &recoveredPtLen);

        if (decRes != HCPABE_SUCCESS)
        {
            secureWipe(&aesKey[0], aesKey.size());
            secureWipe(&recoveredKeyStr[0], recoveredKeyStr.size());
            return decRes;
        }
        std::string recovered = recoveredPtLen ? std::string(reinterpret_cast<const char *>(recoveredPt), recoveredPtLen) : std::string();
        free(recoveredPt);

        // Output plaintext
        *ptLen = recovered.size();
        *plaintext = (unsigned char *)malloc(*ptLen ? *ptLen : 1);
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

int hybrid_cpabe_decrypt_impl(const char *privateKeyFile, const char *ciphertextFile, const char *recovertextFile)
{
    try
    {
        std::string decodedCiphertext;
        try
        {
            CryptoPP::FileSource fileSource(ciphertextFile, true, new CryptoPP::StringSink(decodedCiphertext));
        }
        catch (...)
        {
            return HCPABE_ERR_FILE_NOT_FOUND;
        }

        if (decodedCiphertext.empty())
            return HCPABE_ERR_CRYPTO_FAILED;

        // Auto-detect scheme from version
        uint8_t version = static_cast<uint8_t>(decodedCiphertext[0]);
        CPABEScheme scheme = CPABE_SCHEME_AC17;
        // Old format (AC17 only): FORMAT_VERSION (1 byte) || CP-ABE Ciphertext Length (8 bytes) || ...
        if (version == HybridCPABE::FORMAT_VERSION_2 && decodedCiphertext.size() > 1)
        {
            scheme = static_cast<CPABEScheme>(decodedCiphertext[1]);
        }

        unsigned char *skData = nullptr;
        size_t skLen = 0;
        int loadRes = HCPABE_ERR_FILE_NOT_FOUND;
        switch (scheme)
        {
        case CPABE_SCHEME_AC17:
            loadRes = ac17_load_sk(privateKeyFile, &skData, &skLen);
            break;
        case CPABE_SCHEME_TKN20:
            loadRes = tkn20_load_sk(privateKeyFile, &skData, &skLen);
            break;
        case CPABE_SCHEME_COVERCRYPT:
            loadRes = covercrypt_load_sk(privateKeyFile, &skData, &skLen);
            break;
        }

        if (loadRes != HCPABE_SUCCESS)
            return loadRes;

        unsigned char *ptData = nullptr;
        size_t ptLen = 0;

        int res =
            hybrid_cpabe_decryptBuffer(skData, skLen, reinterpret_cast<const unsigned char *>(decodedCiphertext.data()),
                                       decodedCiphertext.size(), &ptData, &ptLen);

        freeBuffer(skData);

        if (res == HCPABE_SUCCESS)
        {
            try
            {
                CryptoPP::FileSink fileSink(recovertextFile, true);
                fileSink.Put(reinterpret_cast<const CryptoPP::byte *>(ptData), ptLen);
                fileSink.MessageEnd();
                std::cout << "Decryption successful!" << std::endl;
            }
            catch (...)
            {
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

int hybrid_cpabe_decryptBuffer_and_verify_impl(const unsigned char *privateKey, size_t skLen,
                                               const unsigned char *pqcPubKey, size_t pqcPubLen,
                                               const unsigned char *ciphertext, size_t ctLen, unsigned char **plaintext,
                                               size_t *ptLen)
{
    if (!plaintext || !ptLen) return HCPABE_ERR_INVALID_PARAM;
    *plaintext = nullptr;
    *ptLen = 0;
    if (!pqcPubKey || !pqcPubLen) return HCPABE_ERR_INVALID_PARAM;
    unsigned char *payload = nullptr;
    size_t payloadLen = 0;
    // Automatically detect scheme from ciphertext (in hybrid_cpabe_decryptBuffer)
    int res = hybrid_cpabe_decryptBuffer(privateKey, skLen, ciphertext, ctLen, &payload, &payloadLen);
    if (res != HCPABE_SUCCESS)
        return res;

    std::string pqcPubBase64(reinterpret_cast<const char *>(pqcPubKey), pqcPubLen);
    std::string pqcPubRaw;
    CryptoPP::StringSource(pqcPubBase64, true, new CryptoPP::Base64Decoder(new CryptoPP::StringSink(pqcPubRaw)));
    if (pqcPubRaw.size() != ml_dsa_87_public_key_size()) {
        secureWipe(payload, payloadLen);
        freeBuffer(payload);
        return HCPABE_ERR_INVALID_KEY;
    }

    if (payloadLen < 4)
    {
        freeBuffer(payload);
        return HCPABE_ERR_CRYPTO_FAILED;
    }
    uint32_t sig_len_32 = 0;
    std::memcpy(&sig_len_32, payload, 4);
    if (sig_len_32 > payloadLen - 4)
    {
        freeBuffer(payload);
        return HCPABE_ERR_CRYPTO_FAILED;
    }

    const uint8_t *signature = payload + 4;
    const uint8_t *dataToSign = payload + 4 + sig_len_32;
    size_t dataToSignLen = payloadLen - 4 - sig_len_32;

    if (ml_dsa_87_verify(dataToSign, dataToSignLen, signature, sig_len_32, (const unsigned char *)pqcPubRaw.data()) !=
        HCPABE_SUCCESS)
    {
        secureWipe(payload, payloadLen);
        freeBuffer(payload);
        return HCPABE_ERR_SIGNATURE_INVALID;
    }

    if (dataToSignLen < 4)
    {
        secureWipe(payload, payloadLen);
        freeBuffer(payload);
        return HCPABE_ERR_CRYPTO_FAILED;
    }
    uint32_t pol_len_32 = 0;
    std::memcpy(&pol_len_32, dataToSign, 4);

    if (pol_len_32 > dataToSignLen - 4)
    {
        secureWipe(payload, payloadLen);
        freeBuffer(payload);
        return HCPABE_ERR_CRYPTO_FAILED;
    }

    const uint8_t *original_pt = dataToSign + 4 + pol_len_32;
    size_t original_pt_len = dataToSignLen - 4 - pol_len_32;

    *ptLen = original_pt_len;
    *plaintext = (unsigned char *)malloc(*ptLen ? *ptLen : 1);
    if (!*plaintext)
    {
        secureWipe(payload, payloadLen);
        freeBuffer(payload);
        return HCPABE_ERR_MEMORY;
    }
    std::memcpy(*plaintext, original_pt, *ptLen);

    secureWipe(payload, payloadLen);
    freeBuffer(payload);
    return HCPABE_SUCCESS;
}

int hybrid_cpabe_decrypt_and_verify_impl(const char *privateKeyFile, const char *pqcPublicKeyFile,
                                         const char *ciphertextFile, const char *recovertextFile)
{
    std::string skData, pqcPkData, ciphertext;
    if (!LoadFile(privateKeyFile, skData, "Base64") || !LoadFile(pqcPublicKeyFile, pqcPkData, "Base64"))
        return HCPABE_ERR_FILE_NOT_FOUND;

    std::ifstream ctF(ciphertextFile, std::ios::binary);
    if (!ctF)
        return HCPABE_ERR_FILE_NOT_FOUND;
    ciphertext.assign((std::istreambuf_iterator<char>(ctF)), std::istreambuf_iterator<char>());

    unsigned char *pt = nullptr;
    size_t ptLen = 0;
    // Decrypt detects scheme automatically
    int res = hybrid_cpabe_decryptBuffer_and_verify(
        (const unsigned char *)skData.data(), skData.size(), (const unsigned char *)pqcPkData.data(), pqcPkData.size(),
        (const unsigned char *)ciphertext.data(), ciphertext.size(), &pt, &ptLen);

    if (res != HCPABE_SUCCESS)
        return res;

    try
    {
        CryptoPP::FileSink fileSink(recovertextFile, true);
        fileSink.Put(pt, ptLen);
        fileSink.MessageEnd();
    }
    catch (...)
    {
        freeBuffer(pt);
        return HCPABE_ERR_FILE_NOT_FOUND;
    }
    freeBuffer(pt);
    std::cout << "Decrypt & Verify successful!" << std::endl;
    return HCPABE_SUCCESS;
}
