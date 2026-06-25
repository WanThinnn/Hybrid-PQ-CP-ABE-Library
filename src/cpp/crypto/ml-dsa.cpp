#include "hybrid_pq_cp_abe/hybrid-pq-cp-abe.h"
#include <oqs/oqs.h>
#include <cstdlib>

extern "C" {

int ml_dsa_87_generate_keypair(unsigned char **pk, size_t *pk_len, unsigned char **sk, size_t *sk_len) {
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_87);
    if (!sig) return HCPABE_ERR_CRYPTO_FAILED;

    *pk_len = sig->length_public_key;
    *sk_len = sig->length_secret_key;
    *pk = (unsigned char *)malloc(*pk_len);
    *sk = (unsigned char *)malloc(*sk_len);

    if (!*pk || !*sk) {
        if (*pk) free(*pk);
        if (*sk) free(*sk);
        OQS_SIG_free(sig);
        return HCPABE_ERR_MEMORY;
    }

    if (OQS_SIG_keypair(sig, *pk, *sk) != OQS_SUCCESS) {
        free(*pk);
        free(*sk);
        OQS_SIG_free(sig);
        return HCPABE_ERR_CRYPTO_FAILED;
    }

    OQS_SIG_free(sig);
    return HCPABE_SUCCESS;
}

int ml_dsa_87_sign(const unsigned char *msg, size_t msg_len, const unsigned char *sk, unsigned char **signature, size_t *sig_len) {
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_87);
    if (!sig) return HCPABE_ERR_CRYPTO_FAILED;

    *signature = (unsigned char *)malloc(sig->length_signature);
    if (!*signature) {
        OQS_SIG_free(sig);
        return HCPABE_ERR_MEMORY;
    }

    if (OQS_SIG_sign(sig, *signature, sig_len, msg, msg_len, sk) != OQS_SUCCESS) {
        free(*signature);
        OQS_SIG_free(sig);
        return HCPABE_ERR_CRYPTO_FAILED;
    }

    OQS_SIG_free(sig);
    return HCPABE_SUCCESS;
}

int ml_dsa_87_verify(const unsigned char *msg, size_t msg_len, const unsigned char *signature, size_t sig_len, const unsigned char *pk) {
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_87);
    if (!sig) return HCPABE_ERR_CRYPTO_FAILED;

    if (OQS_SIG_verify(sig, msg, msg_len, signature, sig_len, pk) != OQS_SUCCESS) {
        OQS_SIG_free(sig);
        return HCPABE_ERR_SIGNATURE_INVALID;
    }

    OQS_SIG_free(sig);
    return HCPABE_SUCCESS;
}

}
