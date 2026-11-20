#include "pqc-internal.h"
extern "C"
{
    int ml_kem_get_sizes(int parameter, size_t *pk, size_t *sk, size_t *ct, size_t *ss)
    {
        if (pk)
            *pk = 0;
        if (sk)
            *sk = 0;
        if (ct)
            *ct = 0;
        if (ss)
            *ss = 0;
        if (!pk || !sk || !ct || !ss || pk == sk || pk == ct || pk == ss || sk == ct || sk == ss || ct == ss ||
            !pqc::kem_name(parameter))
            return HCPABE_ERR_INVALID_PARAM;
        auto kem = pqc::kem(parameter);
        if (!kem)
            return HCPABE_ERR_CRYPTO_FAILED;
        *pk = kem->length_public_key;
        *sk = kem->length_secret_key;
        *ct = kem->length_ciphertext;
        *ss = kem->length_shared_secret;
        return HCPABE_SUCCESS;
    }
    int ml_kem_generate_keypair(int parameter, unsigned char **pk, size_t *pk_len,
                                unsigned char **sk, size_t *sk_len)
    {
        if (!pqc::outputs(pk, pk_len, sk, sk_len) || !pqc::kem_name(parameter))
            return HCPABE_ERR_INVALID_PARAM;
        auto kem = pqc::kem(parameter);
        if (!kem)
            return HCPABE_ERR_CRYPTO_FAILED;
        auto public_key = pqc::allocate(kem->length_public_key), secret_key = pqc::allocate(kem->length_secret_key);
        if (!public_key || !secret_key)
            return HCPABE_ERR_MEMORY;
        if (OQS_KEM_keypair(kem.get(), public_key.get(), secret_key.get()) != OQS_SUCCESS)
            return HCPABE_ERR_CRYPTO_FAILED;
        *pk_len = kem->length_public_key;
        *sk_len = kem->length_secret_key;
        *pk = public_key.release();
        *sk = secret_key.release();
        return HCPABE_SUCCESS;
    }
    int ml_kem_encapsulate(int parameter, const unsigned char *pk, size_t pk_len,
                           unsigned char **ct, size_t *ct_len, unsigned char **ss, size_t *ss_len)
    {
        if (!pqc::outputs(ct, ct_len, ss, ss_len) || !pk || !pqc::kem_name(parameter))
            return HCPABE_ERR_INVALID_PARAM;
        auto kem = pqc::kem(parameter);
        if (!kem)
            return HCPABE_ERR_CRYPTO_FAILED;
        if (pk_len != kem->length_public_key)
            return HCPABE_ERR_INVALID_KEY;
        auto ciphertext = pqc::allocate(kem->length_ciphertext), secret = pqc::allocate(kem->length_shared_secret);
        if (!ciphertext || !secret)
            return HCPABE_ERR_MEMORY;
        if (OQS_KEM_encaps(kem.get(), ciphertext.get(), secret.get(), pk) != OQS_SUCCESS)
            return HCPABE_ERR_CRYPTO_FAILED;
        *ct_len = kem->length_ciphertext;
        *ss_len = kem->length_shared_secret;
        *ct = ciphertext.release();
        *ss = secret.release();
        return HCPABE_SUCCESS;
    }
    int ml_kem_decapsulate(int parameter, const unsigned char *sk, size_t sk_len,
                           const unsigned char *ct, size_t ct_len, unsigned char **ss, size_t *ss_len)
    {
        if (!pqc::output(ss, ss_len) || !sk || !ct || !pqc::kem_name(parameter))
            return HCPABE_ERR_INVALID_PARAM;
        auto kem = pqc::kem(parameter);
        if (!kem)
            return HCPABE_ERR_CRYPTO_FAILED;
        if (sk_len != kem->length_secret_key)
            return HCPABE_ERR_INVALID_KEY;
        if (ct_len != kem->length_ciphertext)
            return HCPABE_ERR_INVALID_PARAM;
        auto secret = pqc::allocate(kem->length_shared_secret);
        if (!secret)
            return HCPABE_ERR_MEMORY;
        if (OQS_KEM_decaps(kem.get(), secret.get(), ct, sk) != OQS_SUCCESS)
            return HCPABE_ERR_CRYPTO_FAILED;
        *ss_len = kem->length_shared_secret;
        *ss = secret.release();
        return HCPABE_SUCCESS;
    }
}
