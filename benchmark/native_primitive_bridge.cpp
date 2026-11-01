#include "hybrid_pq_cp_abe/cpabe-scheme.h"
#include "hybrid_pq_cp_abe/hybrid-pq-cp-abe.h"

#include <cstddef>

#ifdef _WIN32
#define BENCH_API __declspec(dllexport)
#else
#define BENCH_API __attribute__((visibility("default")))
#endif

namespace
{
int setup_for_scheme(int scheme, unsigned char **pk, size_t *pk_len,
                     unsigned char **msk, size_t *msk_len)
{
    switch (scheme)
    {
    case CPABE_SCHEME_AC17:
        return ac17_setupBuffer(pk, pk_len, msk, msk_len);
    case CPABE_SCHEME_TKN20:
        return tkn20_setupBuffer(pk, pk_len, msk, msk_len);
    case CPABE_SCHEME_COVERCRYPT:
        return covercrypt_setupBuffer(pk, pk_len, msk, msk_len);
    default:
        return HCPABE_ERR_INVALID_PARAM;
    }
}

int genkey_for_scheme(int scheme, const unsigned char *msk, size_t msk_len,
                      const char *attributes, unsigned char **sk, size_t *sk_len)
{
    switch (scheme)
    {
    case CPABE_SCHEME_AC17:
        return ac17_genkeyBuffer(msk, msk_len, attributes, sk, sk_len);
    case CPABE_SCHEME_TKN20:
        return tkn20_genkeyBuffer(msk, msk_len, attributes, sk, sk_len);
    case CPABE_SCHEME_COVERCRYPT:
        return covercrypt_genkeyBuffer(msk, msk_len, attributes, sk, sk_len);
    default:
        return HCPABE_ERR_INVALID_PARAM;
    }
}

int protect_for_scheme(int scheme, const unsigned char *pk, size_t pk_len,
                       const char *policy, const unsigned char *secret, size_t secret_len,
                       unsigned char **ciphertext, size_t *ciphertext_len)
{
    switch (scheme)
    {
    case CPABE_SCHEME_AC17:
        return ac17_encapsulate_key(pk, pk_len, policy, secret, secret_len, ciphertext, ciphertext_len);
    case CPABE_SCHEME_TKN20:
        return tkn20_encapsulate_key(pk, pk_len, policy, secret, secret_len, ciphertext, ciphertext_len);
    case CPABE_SCHEME_COVERCRYPT:
        return covercrypt_encapsulate_key(pk, pk_len, policy, secret, secret_len, ciphertext, ciphertext_len);
    default:
        return HCPABE_ERR_INVALID_PARAM;
    }
}

int recover_for_scheme(int scheme, const unsigned char *sk, size_t sk_len,
                       const unsigned char *ciphertext, size_t ciphertext_len,
                       unsigned char **secret, size_t *secret_len)
{
    switch (scheme)
    {
    case CPABE_SCHEME_AC17:
        return ac17_decapsulate_key(sk, sk_len, ciphertext, ciphertext_len, secret, secret_len);
    case CPABE_SCHEME_TKN20:
        return tkn20_decapsulate_key(sk, sk_len, ciphertext, ciphertext_len, secret, secret_len);
    case CPABE_SCHEME_COVERCRYPT:
        return covercrypt_decapsulate_key(sk, sk_len, ciphertext, ciphertext_len, secret, secret_len);
    default:
        return HCPABE_ERR_INVALID_PARAM;
    }
}
} // namespace

extern "C"
{
BENCH_API int hcpabe_bench_setup(int scheme, unsigned char **pk, size_t *pk_len,
                                 unsigned char **msk, size_t *msk_len)
{
    if (!pk || !pk_len || !msk || !msk_len)
        return HCPABE_ERR_INVALID_PARAM;
    return setup_for_scheme(scheme, pk, pk_len, msk, msk_len);
}

BENCH_API int hcpabe_bench_genkey(int scheme, const unsigned char *msk, size_t msk_len,
                                  const char *attributes, unsigned char **sk, size_t *sk_len)
{
    if (!msk || !msk_len || !attributes || !sk || !sk_len)
        return HCPABE_ERR_INVALID_PARAM;
    return genkey_for_scheme(scheme, msk, msk_len, attributes, sk, sk_len);
}

BENCH_API int hcpabe_bench_protect(int scheme, const unsigned char *pk, size_t pk_len,
                                   const char *policy, const unsigned char *secret, size_t secret_len,
                                   unsigned char **ciphertext, size_t *ciphertext_len)
{
    if (!pk || !pk_len || !policy || !secret || !secret_len || !ciphertext || !ciphertext_len)
        return HCPABE_ERR_INVALID_PARAM;
    return protect_for_scheme(scheme, pk, pk_len, policy, secret, secret_len, ciphertext, ciphertext_len);
}

BENCH_API int hcpabe_bench_recover(int scheme, const unsigned char *sk, size_t sk_len,
                                   const unsigned char *ciphertext, size_t ciphertext_len,
                                   unsigned char **secret, size_t *secret_len)
{
    if (!sk || !sk_len || !ciphertext || !ciphertext_len || !secret || !secret_len)
        return HCPABE_ERR_INVALID_PARAM;
    return recover_for_scheme(scheme, sk, sk_len, ciphertext, ciphertext_len, secret, secret_len);
}

BENCH_API void hcpabe_bench_free(unsigned char *buffer)
{
    freeBuffer(buffer);
}
}
