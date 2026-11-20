#include "pqc-internal.h"

size_t ml_dsa_87_public_key_size() { return OQS_SIG_ml_dsa_87_length_public_key; }
size_t ml_dsa_87_secret_key_size() { return OQS_SIG_ml_dsa_87_length_secret_key; }
size_t ml_dsa_87_signature_size() { return OQS_SIG_ml_dsa_87_length_signature; }

extern "C"
{
    int ml_dsa_get_sizes(int parameter, size_t *pk, size_t *sk, size_t *signature)
    {
        if (pk)
            *pk = 0;
        if (sk)
            *sk = 0;
        if (signature)
            *signature = 0;
        if (!pk || !sk || !signature || pk == sk || pk == signature || sk == signature ||
            !pqc::signature_name(parameter))
            return HCPABE_ERR_INVALID_PARAM;
        auto sig = pqc::signature(parameter);
        if (!sig)
            return HCPABE_ERR_CRYPTO_FAILED;
        *pk = sig->length_public_key;
        *sk = sig->length_secret_key;
        *signature = sig->length_signature;
        return HCPABE_SUCCESS;
    }
    int ml_dsa_generate_keypair(int parameter, unsigned char **pk, size_t *pk_len,
                                unsigned char **sk, size_t *sk_len)
    {
        if (!pqc::outputs(pk, pk_len, sk, sk_len) || !pqc::signature_name(parameter))
            return HCPABE_ERR_INVALID_PARAM;
        auto sig = pqc::signature(parameter);
        if (!sig)
            return HCPABE_ERR_CRYPTO_FAILED;
        auto public_key = pqc::allocate(sig->length_public_key), secret_key = pqc::allocate(sig->length_secret_key);
        if (!public_key || !secret_key)
            return HCPABE_ERR_MEMORY;
        if (OQS_SIG_keypair(sig.get(), public_key.get(), secret_key.get()) != OQS_SUCCESS)
            return HCPABE_ERR_CRYPTO_FAILED;
        *pk_len = sig->length_public_key;
        *sk_len = sig->length_secret_key;
        *pk = public_key.release();
        *sk = secret_key.release();
        return HCPABE_SUCCESS;
    }
    int ml_dsa_sign(int parameter, const unsigned char *msg, size_t msg_len,
                    const unsigned char *sk, size_t sk_len, unsigned char **signature, size_t *sig_len)
    {
        if (!pqc::output(signature, sig_len) || (!msg && msg_len) || !sk || !pqc::signature_name(parameter))
            return HCPABE_ERR_INVALID_PARAM;
        auto sig = pqc::signature(parameter);
        if (!sig)
            return HCPABE_ERR_CRYPTO_FAILED;
        if (sk_len != sig->length_secret_key)
            return HCPABE_ERR_INVALID_KEY;
        auto result = pqc::allocate(sig->length_signature);
        if (!result)
            return HCPABE_ERR_MEMORY;
        size_t length = 0;
        const unsigned char empty = 0;
        if (OQS_SIG_sign(sig.get(), result.get(), &length, msg ? msg : &empty, msg_len, sk) != OQS_SUCCESS)
            return HCPABE_ERR_CRYPTO_FAILED;
        *signature = result.release();
        *sig_len = length;
        return HCPABE_SUCCESS;
    }
    int ml_dsa_verify(int parameter, const unsigned char *msg, size_t msg_len,
                      const unsigned char *signature, size_t sig_len, const unsigned char *pk, size_t pk_len)
    {
        if ((!msg && msg_len) || !signature || !pk || !pqc::signature_name(parameter))
            return HCPABE_ERR_INVALID_PARAM;
        auto sig = pqc::signature(parameter);
        if (!sig)
            return HCPABE_ERR_CRYPTO_FAILED;
        if (pk_len != sig->length_public_key)
            return HCPABE_ERR_INVALID_KEY;
        if (sig_len != sig->length_signature)
            return HCPABE_ERR_SIGNATURE_INVALID;
        const unsigned char empty = 0;
        return OQS_SIG_verify(sig.get(), msg ? msg : &empty, msg_len, signature, sig_len, pk) == OQS_SUCCESS
                   ? HCPABE_SUCCESS
                   : HCPABE_ERR_SIGNATURE_INVALID;
    }
    int ml_dsa_87_generate_keypair(unsigned char **pk, size_t *pk_len, unsigned char **sk, size_t *sk_len)
    {
        return ml_dsa_generate_keypair(87, pk, pk_len, sk, sk_len);
    }
    int ml_dsa_87_sign(const unsigned char *msg, size_t msg_len, const unsigned char *sk,
                       unsigned char **signature, size_t *sig_len)
    {
        return ml_dsa_sign(87, msg, msg_len, sk, ml_dsa_87_secret_key_size(), signature, sig_len);
    }
    int ml_dsa_87_verify(const unsigned char *msg, size_t msg_len, const unsigned char *signature,
                         size_t sig_len, const unsigned char *pk)
    {
        return ml_dsa_verify(87, msg, msg_len, signature, sig_len, pk, ml_dsa_87_public_key_size());
    }
}
