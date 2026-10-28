#include "abe-internal.h"
#include <cryptopp/sha3.h>

int hybrid_cpabe_encryptBuffer_with_scheme_impl(const unsigned char *publicKey, size_t pkLen,
                                                const unsigned char *plaintext, size_t ptLen, const char *policy,
                                                unsigned char **ciphertext, size_t *ctLen, CPABEScheme scheme)
{
    if (!ciphertext || !ctLen) return HCPABE_ERR_INVALID_PARAM;
    *ciphertext = nullptr;
    *ctLen = 0;
    std::string aesKey;
    std::string randomKeyStr;

    try
    {
        if (!publicKey || !pkLen || (!plaintext && ptLen) || !policy)
            return HCPABE_ERR_INVALID_PARAM;

        CryptoPP::AutoSeededRandomPool prng;
        CryptoPP::Integer randomKey(prng, 12288);
        randomKey.Encode(CryptoPP::StringSink(randomKeyStr).Ref(), randomKey.MinEncodedSize());

        unsigned char *encryptedAbeKey = nullptr;
        size_t encryptedAbeKeyLen = 0;
        int abeRes = HCPABE_ERR_INVALID_PARAM;

        switch (scheme)
        {
        case CPABE_SCHEME_AC17:
            abeRes = ac17_encapsulate_key(publicKey, pkLen, policy,
                                          reinterpret_cast<const unsigned char *>(randomKeyStr.data()),
                                          randomKeyStr.size(), &encryptedAbeKey, &encryptedAbeKeyLen);
            break;
        case CPABE_SCHEME_TKN20:
            abeRes = tkn20_encapsulate_key(publicKey, pkLen, policy,
                                           reinterpret_cast<const unsigned char *>(randomKeyStr.data()),
                                           randomKeyStr.size(), &encryptedAbeKey, &encryptedAbeKeyLen);
            break;
        case CPABE_SCHEME_COVERCRYPT:
            abeRes = covercrypt_encapsulate_key(publicKey, pkLen, policy,
                                                reinterpret_cast<const unsigned char *>(randomKeyStr.data()),
                                                randomKeyStr.size(), &encryptedAbeKey, &encryptedAbeKeyLen);
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
        aad.push_back(static_cast<char>(scheme));                        // scheme identifier byte
        aad.append(reinterpret_cast<const char *>(iv), sizeof(iv));
        uint64_t lenEncryptedKey = encryptedAbeKeyLen;
        aad.append(reinterpret_cast<const char *>(&lenEncryptedKey), sizeof(lenEncryptedKey));
        aad.append(reinterpret_cast<const char *>(encryptedAbeKey), encryptedAbeKeyLen);

        freeBuffer(encryptedAbeKey);

        unsigned char *aesCiphertext = nullptr;
        size_t aesCtLen = 0;
        int aesRes = aes_gcm_encrypt(reinterpret_cast<const unsigned char *>(aesKey.data()), aesKey.size(), iv,
                                     sizeof(iv), plaintext, ptLen, reinterpret_cast<const unsigned char *>(aad.data()),
                                     aad.size(), &aesCiphertext, &aesCtLen);

        if (aesRes != HCPABE_SUCCESS)
        {
            secureWipe(&aesKey[0], aesKey.size());
            secureWipe(&randomKeyStr[0], randomKeyStr.size());
            return aesRes;
        }

        // Combine parts
        std::string combined;
        combined.append(aad);
        combined.append(reinterpret_cast<const char *>(aesCiphertext), aesCtLen);
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

int hybrid_cpabe_encryptBuffer_impl(const unsigned char *publicKey, size_t pkLen, const unsigned char *plaintext,
                                    size_t ptLen, const char *policy, unsigned char **ciphertext, size_t *ctLen)
{
    // Call with legacy mode (AC17) but save under format_version_2 (containing AC17 scheme byte)
    // because if this function is called, we still want to encrypt correctly and be compatible. However,
    // to be fully compatible with old ciphertexts, we should create a FORMAT_VERSION (0x01) ciphertext.
    // To keep the code cleaner, here if the user does not specify, we fallback to AC17.
    // Actually the encryptBuffer_with_scheme uses FORMAT_VERSION_2.
    // New format: FORMAT_VERSION_2 (1 byte) || Scheme ID (1 byte) || CP-ABE Ciphertext Length (8 bytes) || IV (12
    // bytes) || Encrypted CP-ABE Key || GCM Tag || AES Ciphertext. Decrypt will recognize v2 and AC17 scheme.
    return hybrid_cpabe_encryptBuffer_with_scheme(publicKey, pkLen, plaintext, ptLen, policy, ciphertext, ctLen,
                                                  CPABE_SCHEME_AC17);
}

int hybrid_cpabe_encrypt_with_scheme_impl(const char *publicKeyFile, const char *plaintextFile, const char *policy,
                                          const char *ciphertextFile, CPABEScheme scheme)
{
    unsigned char *pkData = nullptr;
    size_t pkLen = 0;
    int loadRes = HCPABE_ERR_FILE_NOT_FOUND;

    switch (scheme)
    {
    case CPABE_SCHEME_AC17:
        loadRes = ac17_load_pk(publicKeyFile, &pkData, &pkLen);
        break;
    case CPABE_SCHEME_TKN20:
        loadRes = tkn20_load_pk(publicKeyFile, &pkData, &pkLen);
        break;
    case CPABE_SCHEME_COVERCRYPT:
        loadRes = covercrypt_load_pk(publicKeyFile, &pkData, &pkLen);
        break;
    }

    if (loadRes != HCPABE_SUCCESS)
        return loadRes;

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

    int res =
        hybrid_cpabe_encryptBuffer_with_scheme(pkData, pkLen, reinterpret_cast<const unsigned char *>(plaintext.data()),
                                               plaintext.size(), policy, &ctData, &ctLen, scheme);

    freeBuffer(pkData);

    if (res == HCPABE_SUCCESS)
    {
        try
        {
            CryptoPP::FileSink fileSink(ciphertextFile, true);
            fileSink.Put(reinterpret_cast<const CryptoPP::byte *>(ctData), ctLen);
            fileSink.MessageEnd();
            std::cout << "Encryption successful!" << std::endl;
        }
        catch (...)
        {
            res = HCPABE_ERR_FILE_NOT_FOUND;
        }
        freeBuffer(ctData);
    }

    return res;
}

int hybrid_cpabe_encrypt_impl(const char *publicKeyFile, const char *plaintextFile, const char *policy,
                              const char *ciphertextFile)
{
    return hybrid_cpabe_encrypt_with_scheme(publicKeyFile, plaintextFile, policy, ciphertextFile, CPABE_SCHEME_AC17);
}

int hybrid_cpabe_encryptBuffer_and_sign_with_scheme_impl(const unsigned char *publicKey, size_t pkLen,
                                                         const unsigned char *pqcPrivKey, size_t pqcPrivLen,
                                                         const unsigned char *plaintext, size_t ptLen,
                                                         const char *policy, unsigned char **ciphertext, size_t *ctLen,
                                                         CPABEScheme scheme)
{
    if (!ciphertext || !ctLen) return HCPABE_ERR_INVALID_PARAM;
    *ciphertext = nullptr;
    *ctLen = 0;
    if (!publicKey || !pkLen || !pqcPrivKey || !pqcPrivLen || (!plaintext && ptLen) || !policy)
        return HCPABE_ERR_INVALID_PARAM;
    std::string pqcPrivBase64(reinterpret_cast<const char *>(pqcPrivKey), pqcPrivLen);
    std::string pqcPrivRaw;
    CryptoPP::StringSource(pqcPrivBase64, true, new CryptoPP::Base64Decoder(new CryptoPP::StringSink(pqcPrivRaw)));
    if (pqcPrivRaw.size() != ml_dsa_87_secret_key_size()) {
        if (!pqcPrivRaw.empty()) secureWipe(&pqcPrivRaw[0], pqcPrivRaw.size());
        return HCPABE_ERR_INVALID_KEY;
    }

    uint32_t pol_len_32 = static_cast<uint32_t>(strlen(policy));
    std::vector<uint8_t> dataToSign;
    dataToSign.reserve(4 + pol_len_32 + ptLen);
    uint8_t *plen_ptr = reinterpret_cast<uint8_t *>(&pol_len_32);
    dataToSign.insert(dataToSign.end(), plen_ptr, plen_ptr + 4);
    dataToSign.insert(dataToSign.end(), reinterpret_cast<const uint8_t *>(policy),
                      reinterpret_cast<const uint8_t *>(policy) + pol_len_32);
    if (ptLen) dataToSign.insert(dataToSign.end(), plaintext, plaintext + ptLen);

    unsigned char *signature = nullptr;
    size_t sig_len = 0;
    if (ml_dsa_87_sign(dataToSign.data(), dataToSign.size(), (const unsigned char *)pqcPrivRaw.data(), &signature,
                       &sig_len) != HCPABE_SUCCESS)
    {
        return HCPABE_ERR_CRYPTO_FAILED;
    }

    uint32_t sig_len_32 = static_cast<uint32_t>(sig_len);
    std::vector<uint8_t> payload;
    payload.reserve(4 + sig_len + dataToSign.size());
    uint8_t *slen_ptr = reinterpret_cast<uint8_t *>(&sig_len_32);
    payload.insert(payload.end(), slen_ptr, slen_ptr + 4);
    payload.insert(payload.end(), signature, signature + sig_len);
    payload.insert(payload.end(), dataToSign.begin(), dataToSign.end());

    int res = hybrid_cpabe_encryptBuffer_with_scheme(publicKey, pkLen, payload.data(), payload.size(), policy,
                                                     ciphertext, ctLen, scheme);
    if (res != HCPABE_SUCCESS)
    {
        std::cout << "DEBUG: hybrid_cpabe_encryptBuffer_with_scheme returned " << res << std::endl;
    }

    secureWipe(&pqcPrivRaw[0], pqcPrivRaw.size());
    secureWipe(payload.data(), payload.size());
    if (signature)
        free(signature);
    return res;
}

int hybrid_cpabe_encryptBuffer_and_sign_impl(const unsigned char *publicKey, size_t pkLen,
                                             const unsigned char *pqcPrivKey, size_t pqcPrivLen,
                                             const unsigned char *plaintext, size_t ptLen, const char *policy,
                                             unsigned char **ciphertext, size_t *ctLen)
{
    return hybrid_cpabe_encryptBuffer_and_sign_with_scheme(publicKey, pkLen, pqcPrivKey, pqcPrivLen, plaintext, ptLen,
                                                           policy, ciphertext, ctLen, CPABE_SCHEME_AC17);
}

int hybrid_cpabe_encrypt_and_sign_with_scheme_impl(const char *publicKeyFile, const char *pqcPrivateKeyFile,
                                                   const char *plaintextFile, const char *policy,
                                                   const char *ciphertextFile, CPABEScheme scheme)
{
    std::string pkData, pqcSkData, plaintext;
    if (!LoadFile(publicKeyFile, pkData, "Base64") || !LoadFile(pqcPrivateKeyFile, pqcSkData, "Base64"))
        return HCPABE_ERR_FILE_NOT_FOUND;

    std::ifstream ptF(plaintextFile, std::ios::binary);
    if (!ptF)
        return HCPABE_ERR_FILE_NOT_FOUND;
    plaintext.assign((std::istreambuf_iterator<char>(ptF)), std::istreambuf_iterator<char>());

    unsigned char *ct = nullptr;
    size_t ctLen = 0;
    int res = hybrid_cpabe_encryptBuffer_and_sign_with_scheme(
        (const unsigned char *)pkData.data(), pkData.size(), (const unsigned char *)pqcSkData.data(), pqcSkData.size(),
        (const unsigned char *)plaintext.data(), plaintext.size(), policy, &ct, &ctLen, scheme);

    if (res != HCPABE_SUCCESS)
        return res;

    try
    {
        CryptoPP::FileSink fileSink(ciphertextFile, true);
        fileSink.Put(ct, ctLen);
        fileSink.MessageEnd();
    }
    catch (...)
    {
        freeBuffer(ct);
        return HCPABE_ERR_FILE_NOT_FOUND;
    }
    freeBuffer(ct);
    std::cout << "Encrypt & Sign successful!" << std::endl;
    return HCPABE_SUCCESS;
}

int hybrid_cpabe_encrypt_and_sign_impl(const char *publicKeyFile, const char *pqcPrivateKeyFile,
                                       const char *plaintextFile, const char *policy, const char *ciphertextFile)
{
    return hybrid_cpabe_encrypt_and_sign_with_scheme(publicKeyFile, pqcPrivateKeyFile, plaintextFile, policy,
                                                     ciphertextFile, CPABE_SCHEME_AC17);
}
