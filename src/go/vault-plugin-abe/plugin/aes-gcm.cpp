#include "hybrid_pq_cp_abe/hybrid-pq-cp-abe.h"
#include "hybrid_pq_cp_abe/common-utils.h"
#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/filters.h>
#include <iostream>

extern "C" {

int aes_gcm_encrypt(
    const unsigned char* key, size_t key_len,
    const unsigned char* iv, size_t iv_len,
    const unsigned char* plaintext, size_t pt_len,
    const unsigned char* aad, size_t aad_len,
    unsigned char** ciphertext, size_t* ct_len)
{
    try {
        if (!key || !iv || !ciphertext || !ct_len) return HCPABE_ERR_INVALID_PARAM;
        if (pt_len > 0 && !plaintext) return HCPABE_ERR_INVALID_PARAM;

        CryptoPP::GCM<CryptoPP::AES>::Encryption aes_gcm;
        aes_gcm.SetKeyWithIV(key, key_len, iv, iv_len);

        std::string aesCiphertext;
        CryptoPP::AuthenticatedEncryptionFilter ef(aes_gcm, new CryptoPP::StringSink(aesCiphertext));

        // Add AAD
        if (aad && aad_len > 0) {
            ef.ChannelPut(CryptoPP::AAD_CHANNEL, aad, aad_len);
            ef.ChannelMessageEnd(CryptoPP::AAD_CHANNEL);
        }

        // Add Plaintext
        if (plaintext && pt_len > 0) {
            ef.ChannelPut(CryptoPP::DEFAULT_CHANNEL, plaintext, pt_len);
        }
        ef.ChannelMessageEnd(CryptoPP::DEFAULT_CHANNEL);

        *ct_len = aesCiphertext.size();
        *ciphertext = (unsigned char*)malloc(*ct_len);
        if (!*ciphertext) return HCPABE_ERR_MEMORY;
        
        std::memcpy(*ciphertext, aesCiphertext.data(), *ct_len);
        return HCPABE_SUCCESS;
    } catch (const CryptoPP::Exception& e) {
        std::cerr << "AES-GCM Encrypt Crypto++ Error: " << e.what() << std::endl;
        return HCPABE_ERR_CRYPTO_FAILED;
    } catch (...) {
        return HCPABE_ERR_CRYPTO_FAILED;
    }
}

int aes_gcm_decrypt(
    const unsigned char* key, size_t key_len,
    const unsigned char* iv, size_t iv_len,
    const unsigned char* ciphertext, size_t ct_len,
    const unsigned char* aad, size_t aad_len,
    unsigned char** plaintext, size_t* pt_len)
{
    try {
        if (!key || !iv || !ciphertext || !plaintext || !pt_len) return HCPABE_ERR_INVALID_PARAM;

        CryptoPP::GCM<CryptoPP::AES>::Decryption aes_gcm;
        aes_gcm.SetKeyWithIV(key, key_len, iv, iv_len);

        std::string recovered;
        CryptoPP::AuthenticatedDecryptionFilter df(aes_gcm, new CryptoPP::StringSink(recovered), CryptoPP::AuthenticatedDecryptionFilter::DEFAULT_FLAGS);

        // Put AAD
        if (aad && aad_len > 0) {
            df.ChannelPut(CryptoPP::AAD_CHANNEL, aad, aad_len);
            df.ChannelMessageEnd(CryptoPP::AAD_CHANNEL);
        }

        // Put Ciphertext
        df.ChannelPut(CryptoPP::DEFAULT_CHANNEL, ciphertext, ct_len);
        df.ChannelMessageEnd(CryptoPP::DEFAULT_CHANNEL);

        if (!df.GetLastResult()) {
            return HCPABE_ERR_CRYPTO_FAILED;
        }

        *pt_len = recovered.size();
        if (*pt_len > 0) {
            *plaintext = (unsigned char*)malloc(*pt_len);
            if (!*plaintext) return HCPABE_ERR_MEMORY;
            std::memcpy(*plaintext, recovered.data(), *pt_len);
        } else {
            *plaintext = nullptr;
        }

        return HCPABE_SUCCESS;
    } catch (const CryptoPP::Exception& e) {
        std::cerr << "AES-GCM Decrypt Crypto++ Error: " << e.what() << std::endl;
        return HCPABE_ERR_CRYPTO_FAILED;
    } catch (...) {
        return HCPABE_ERR_CRYPTO_FAILED;
    }
}

}
