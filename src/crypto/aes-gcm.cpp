#include "hybrid_pq_cp_abe/hybrid-pq-cp-abe.h"
#include "hybrid_pq_cp_abe/common-utils.h"
#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>
#include <memory>
#include <iostream>

extern "C"
{
    int aes_gcm_generate_key(int bits, unsigned char **key, size_t *key_len)
    {
        if (key)
            *key = nullptr;
        if (key_len)
            *key_len = 0;
        if (!key || !key_len || (bits != 128 && bits != 192 && bits != 256))
            return HCPABE_ERR_INVALID_PARAM;
        try
        {
            const size_t length = static_cast<size_t>(bits / 8);
            std::unique_ptr<unsigned char, decltype(&std::free)> result(
                static_cast<unsigned char *>(std::malloc(length)), &std::free);
            if (!result)
                return HCPABE_ERR_MEMORY;
            CryptoPP::AutoSeededRandomPool rng;
            rng.GenerateBlock(result.get(), length);
            *key_len = length;
            *key = result.release();
            return HCPABE_SUCCESS;
        }
        catch (...)
        {
            return HCPABE_ERR_CRYPTO_FAILED;
        }
    }

    int aes_gcm_encrypt(
        const unsigned char *key, size_t key_len,
        const unsigned char *iv, size_t iv_len,
        const unsigned char *plaintext, size_t pt_len,
        const unsigned char *aad, size_t aad_len,
        unsigned char **ciphertext, size_t *ct_len)
    {
        if (ciphertext)
            *ciphertext = nullptr;
        if (ct_len)
            *ct_len = 0;
        try
        {
            if (!key || !iv || !ciphertext || !ct_len)
                return HCPABE_ERR_INVALID_PARAM;
            if ((key_len != 16 && key_len != 24 && key_len != 32) || !iv_len ||
                (aad_len && !aad) || (pt_len > 0 && !plaintext))
                return HCPABE_ERR_INVALID_PARAM;

            CryptoPP::GCM<CryptoPP::AES>::Encryption aes_gcm;
            aes_gcm.SetKeyWithIV(key, key_len, iv, iv_len);

            std::string aesCiphertext;
            CryptoPP::AuthenticatedEncryptionFilter ef(aes_gcm, new CryptoPP::StringSink(aesCiphertext));

            // Add AAD
            if (aad && aad_len > 0)
            {
                ef.ChannelPut(CryptoPP::AAD_CHANNEL, aad, aad_len);
                ef.ChannelMessageEnd(CryptoPP::AAD_CHANNEL);
            }

            // Add Plaintext
            if (plaintext && pt_len > 0)
            {
                ef.ChannelPut(CryptoPP::DEFAULT_CHANNEL, plaintext, pt_len);
            }
            ef.ChannelMessageEnd(CryptoPP::DEFAULT_CHANNEL);

            *ciphertext = (unsigned char *)malloc(aesCiphertext.size());
            if (!*ciphertext)
                return HCPABE_ERR_MEMORY;

            *ct_len = aesCiphertext.size();

            std::memcpy(*ciphertext, aesCiphertext.data(), *ct_len);
            return HCPABE_SUCCESS;
        }
        catch (const CryptoPP::Exception &e)
        {
            std::cerr << "AES-GCM Encrypt Crypto++ Error: " << e.what() << std::endl;
            return HCPABE_ERR_CRYPTO_FAILED;
        }
        catch (...)
        {
            return HCPABE_ERR_CRYPTO_FAILED;
        }
    }

    int aes_gcm_decrypt(
        const unsigned char *key, size_t key_len,
        const unsigned char *iv, size_t iv_len,
        const unsigned char *ciphertext, size_t ct_len,
        const unsigned char *aad, size_t aad_len,
        unsigned char **plaintext, size_t *pt_len)
    {
        if (plaintext)
            *plaintext = nullptr;
        if (pt_len)
            *pt_len = 0;
        try
        {
            if (!key || !iv || !ciphertext || !plaintext || !pt_len)
                return HCPABE_ERR_INVALID_PARAM;
            if ((key_len != 16 && key_len != 24 && key_len != 32) || !iv_len ||
                (aad_len && !aad) || ct_len < 16)
                return HCPABE_ERR_INVALID_PARAM;

            CryptoPP::GCM<CryptoPP::AES>::Decryption aes_gcm;
            aes_gcm.SetKeyWithIV(key, key_len, iv, iv_len);

            std::string recovered;
            CryptoPP::AuthenticatedDecryptionFilter df(aes_gcm, new CryptoPP::StringSink(recovered), CryptoPP::AuthenticatedDecryptionFilter::DEFAULT_FLAGS);

            // Put AAD
            if (aad && aad_len > 0)
            {
                df.ChannelPut(CryptoPP::AAD_CHANNEL, aad, aad_len);
                df.ChannelMessageEnd(CryptoPP::AAD_CHANNEL);
            }

            // Put Ciphertext
            df.ChannelPut(CryptoPP::DEFAULT_CHANNEL, ciphertext, ct_len);
            df.ChannelMessageEnd(CryptoPP::DEFAULT_CHANNEL);

            if (!df.GetLastResult())
            {
                return HCPABE_ERR_CRYPTO_FAILED;
            }

            if (!recovered.empty())
            {
                *plaintext = (unsigned char *)malloc(recovered.size());
                if (!*plaintext)
                    return HCPABE_ERR_MEMORY;
                std::memcpy(*plaintext, recovered.data(), recovered.size());
            }
            else
            {
                *plaintext = nullptr;
            }
            *pt_len = recovered.size();

            return HCPABE_SUCCESS;
        }
        catch (const CryptoPP::Exception &)
        {
            return HCPABE_ERR_CRYPTO_FAILED;
        }
        catch (...)
        {
            return HCPABE_ERR_CRYPTO_FAILED;
        }
    }
}
