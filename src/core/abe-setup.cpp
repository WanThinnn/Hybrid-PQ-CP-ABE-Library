#include "abe-internal.h"

// Scheme setup and optional ML-DSA key generation.

int setup_with_scheme_impl(const char *path, CPABEScheme scheme)
{
    switch (scheme)
    {
    case CPABE_SCHEME_AC17:
        return ac17_setup(path);
    case CPABE_SCHEME_TKN20:
        return tkn20_setup(path);
    case CPABE_SCHEME_COVERCRYPT:
        return covercrypt_setup(path);
    default:
        return HCPABE_ERR_INVALID_PARAM;
    }
}

int setup_impl(const char *path)
{
    // Backward compatibility: default to AC17
    return setup_with_scheme(path, CPABE_SCHEME_AC17);
}

int hybrid_cpabe_setupBuffer_with_scheme_impl(unsigned char **pkBuffer, size_t *pkLen, unsigned char **mskBuffer,
                                              size_t *mskLen, CPABEScheme scheme)
{
    if (!pkBuffer || !pkLen || !mskBuffer || !mskLen)
        return HCPABE_ERR_INVALID_PARAM;
    if (scheme == CPABE_SCHEME_AC17)
    {
        return ac17_setupBuffer(pkBuffer, pkLen, mskBuffer, mskLen);
    }
    else if (scheme == CPABE_SCHEME_TKN20)
    {
        return tkn20_setupBuffer(pkBuffer, pkLen, mskBuffer, mskLen);
    }
    else if (scheme == CPABE_SCHEME_COVERCRYPT)
    {
        return covercrypt_setupBuffer(pkBuffer, pkLen, mskBuffer, mskLen);
    }
    return HCPABE_ERR_INVALID_PARAM;
}

int hybrid_cpabe_setup_with_pqc_scheme_impl(const char *path, CPABEScheme scheme)
{
    // First run the regular CP-ABE setup
    int abeRes = setup_with_scheme(path, scheme);
    if (abeRes != HCPABE_SUCCESS)
        return abeRes;

    std::string strPath(path);
    std::string strFileFormat = HybridCPABE::DEFAULT_KEY_FORMAT;
    unsigned char *pqc_pub = nullptr, *pqc_priv = nullptr;
    size_t pqc_pub_len = 0, pqc_priv_len = 0;

    try
    {
        if (ml_dsa_87_generate_keypair(&pqc_pub, &pqc_pub_len, &pqc_priv, &pqc_priv_len) != HCPABE_SUCCESS)
        {
            throw std::runtime_error("Failed to generate PQC keypair.");
        }

        std::string pqcPubBase64, pqcSecBase64;
        CryptoPP::StringSource(pqc_pub, pqc_pub_len, true,
                               new CryptoPP::Base64Encoder(new CryptoPP::StringSink(pqcPubBase64), false));
        CryptoPP::StringSource(pqc_priv, pqc_priv_len, true,
                               new CryptoPP::Base64Encoder(new CryptoPP::StringSink(pqcSecBase64), false));

        std::string pqcMskPath, pqcPkPath;
        struct stat info;
        if (stat(strPath.c_str(), &info) == 0 && (info.st_mode & S_IFDIR))
        {
            pqcMskPath = strPath + "/pqc_sk.key";
            pqcPkPath = strPath + "/pqc_pk.key";
        }
        else if (strPath.empty() || strPath.back() == '/' || strPath.back() == '\\')
        {
            pqcMskPath = strPath + "pqc_sk.key";
            pqcPkPath = strPath + "pqc_pk.key";
        }
        else
        {
            pqcMskPath = strPath + "_pqc_sk.key";
            pqcPkPath = strPath + "_pqc_pk.key";
        }

        if (strFileFormat == "JsonText" || strFileFormat == "HEX" || strFileFormat == "Base64")
        {
            bool pqcMsSaved = SaveFile(pqcMskPath, pqcSecBase64.c_str(), strFileFormat);
            bool pqcPbSaved = SaveFile(pqcPkPath, pqcPubBase64.c_str(), strFileFormat);

            if (pqc_pub)
                free(pqc_pub);
            if (pqc_priv)
                free(pqc_priv);

            if (!pqcMsSaved || !pqcPbSaved)
                return HCPABE_ERR_FILE_NOT_FOUND;

            std::cout << "PQC Setup completed successfully." << std::endl;
            return HCPABE_SUCCESS;
        }
        else
        {
            throw std::invalid_argument("Unsupported format.");
        }
    }
    catch (...)
    {
        if (pqc_pub)
            free(pqc_pub);
        if (pqc_priv)
            free(pqc_priv);
        return HCPABE_ERR_CRYPTO_FAILED;
    }
}

int hybrid_cpabe_setup_with_pqc_impl(const char *path)
{
    return hybrid_cpabe_setup_with_pqc_scheme(path, CPABE_SCHEME_AC17);
}

int hybrid_cpabe_setupBuffer_with_pqc_scheme_impl(unsigned char **abePkBuffer, size_t *abePkLen,
                                                  unsigned char **abeMskBuffer, size_t *abeMskLen,
                                                  unsigned char **pqcPkBuffer, size_t *pqcPkLen,
                                                  unsigned char **pqcMskBuffer, size_t *pqcMskLen, CPABEScheme scheme)
{
    int abeRes = hybrid_cpabe_setupBuffer_with_scheme(abePkBuffer, abePkLen, abeMskBuffer, abeMskLen, scheme);
    if (abeRes != HCPABE_SUCCESS)
        return abeRes;

    unsigned char *pqc_pub = nullptr, *pqc_priv = nullptr;
    size_t pqc_pub_len = 0, pqc_priv_len = 0;

    try
    {
        if (ml_dsa_87_generate_keypair(&pqc_pub, &pqc_pub_len, &pqc_priv, &pqc_priv_len) != HCPABE_SUCCESS)
        {
            throw std::runtime_error("Failed to generate PQC keypair.");
        }

        std::string pqcPubBase64, pqcSecBase64;
        CryptoPP::StringSource(pqc_pub, pqc_pub_len, true,
                               new CryptoPP::Base64Encoder(new CryptoPP::StringSink(pqcPubBase64), false));
        CryptoPP::StringSource(pqc_priv, pqc_priv_len, true,
                               new CryptoPP::Base64Encoder(new CryptoPP::StringSink(pqcSecBase64), false));

        *pqcPkLen = pqcPubBase64.size();
        *pqcPkBuffer = (unsigned char *)malloc(*pqcPkLen);
        if (!*pqcPkBuffer)
            throw std::bad_alloc();
        std::memcpy(*pqcPkBuffer, pqcPubBase64.data(), *pqcPkLen);

        *pqcMskLen = pqcSecBase64.size();
        *pqcMskBuffer = (unsigned char *)malloc(*pqcMskLen);
        if (!*pqcMskBuffer)
            throw std::bad_alloc();
        std::memcpy(*pqcMskBuffer, pqcSecBase64.data(), *pqcMskLen);

        if (pqc_pub)
            free(pqc_pub);
        if (pqc_priv)
            free(pqc_priv);

        return HCPABE_SUCCESS;
    }
    catch (...)
    {
        if (pqc_pub)
            free(pqc_pub);
        if (pqc_priv)
            free(pqc_priv);
        return HCPABE_ERR_CRYPTO_FAILED;
    }
}
