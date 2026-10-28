#include "abe-internal.h"

// User-key generation; CoverCrypt file mode persists authority state.

int generateSecretKey_with_scheme_impl(const char *masterKeyFile, const char *attributes, const char *privateKeyFile,
                                       CPABEScheme scheme)
{
    switch (scheme)
    {
    case CPABE_SCHEME_AC17:
        return ac17_genkey(masterKeyFile, attributes, privateKeyFile);
    case CPABE_SCHEME_TKN20:
        return tkn20_genkey(masterKeyFile, attributes, privateKeyFile);
    case CPABE_SCHEME_COVERCRYPT:
        return covercrypt_genkey(masterKeyFile, attributes, privateKeyFile);
    default:
        return HCPABE_ERR_INVALID_PARAM;
    }
}

int generateSecretKey_impl(const char *masterKeyFile, const char *attributes, const char *privateKeyFile)
{
    return generateSecretKey_with_scheme(masterKeyFile, attributes, privateKeyFile, CPABE_SCHEME_AC17);
}

int hybrid_cpabe_genkeyBuffer_with_scheme_impl(const unsigned char *mskBuffer, size_t mskLen, const char *attributes,
                                               unsigned char **skBuffer, size_t *skLen, CPABEScheme scheme)
{
    if (!mskBuffer || mskLen == 0 || !attributes || !skBuffer || !skLen)
        return HCPABE_ERR_INVALID_PARAM;
    if (scheme == CPABE_SCHEME_AC17)
    {
        return ac17_genkeyBuffer(mskBuffer, mskLen, attributes, skBuffer, skLen);
    }
    else if (scheme == CPABE_SCHEME_TKN20)
    {
        return tkn20_genkeyBuffer(mskBuffer, mskLen, attributes, skBuffer, skLen);
    }
    else if (scheme == CPABE_SCHEME_COVERCRYPT)
    {
        return covercrypt_genkeyBuffer(mskBuffer, mskLen, attributes, skBuffer, skLen);
    }
    return HCPABE_ERR_INVALID_PARAM;
}
