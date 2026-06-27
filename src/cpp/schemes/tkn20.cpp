/**
 * @file tkn20.cpp
 * @brief TKN20 CP-ABE scheme implementation using Go CIRCL DLL
 * 
 * Provides CP-ABE operations for the TKN20 scheme:
 * Setup, KeyGen, Encrypt, Decrypt, Load keys
 * 
 * Policy and attributes are input by the user in AC17 format,
 * this file automatically converts them to TKN20 format (key:value).
 */

#include "hybrid_pq_cp_abe/cpabe-scheme.h"
#include "hybrid_pq_cp_abe/hybrid-pq-cp-abe.h"
#include "hybrid_pq_cp_abe/common-utils.h"
#include "tkn20/cpabe_tkn20.h"

#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <algorithm>
#include <cstring>

// ============================================================================
// Internal Helpers - Policy/Attribute Conversion
// ============================================================================

// Convert policy from AC17 format to TKN20 format
// AC17: admin AND it          → TKN20: admin:admin and it:it
// AC17: (admin OR it) AND cs  → TKN20: (admin:admin or it:it) and cs:cs
static std::string convertPolicyToTKN20(const std::string &input)
{
    std::string lowerInput = toLowerCase(input);
    std::istringstream iss(lowerInput);
    std::string token;
    std::vector<std::string> tokens;

    while (iss >> token)
    {
        size_t start = 0, end = 0;
        while (end < token.size())
        {
            if (token[end] == '(' || token[end] == ')')
            {
                if (start != end)
                {
                    std::string part = token.substr(start, end - start);
                    // Remove double quotes if present
                    if (!part.empty() && part.front() == '"') part = part.substr(1);
                    if (!part.empty() && part.back() == '"') part.pop_back();
                    if (part == "and" || part == "or" || part == "not")
                    {
                        tokens.push_back(part);
                    }
                    else if (!part.empty())
                    {
                        if (part.find(':') != std::string::npos) {
                            tokens.push_back(part);
                        } else {
                            tokens.push_back(part + ":" + part);
                        }
                    }
                }
                tokens.push_back(std::string(1, token[end]));
                start = end + 1;
            }
            end++;
        }
        if (start != end)
        {
            std::string part = token.substr(start, end - start);
            // Remove double quotes if present
            if (!part.empty() && part.front() == '"') part = part.substr(1);
            if (!part.empty() && part.back() == '"') part.pop_back();
            if (part == "and" || part == "or" || part == "not")
            {
                tokens.push_back(part);
            }
            else if (!part.empty())
            {
                if (part.find(':') != std::string::npos) {
                    tokens.push_back(part);
                } else {
                    tokens.push_back(part + ":" + part);
                }
            }
        }
    }

    // Post-process: CIRCL TKN20 parser requires "not" to be followed by
    // a parenthesized group, e.g. "not (hr:hr)". If "not" is followed by
    // a bare attribute (not "("), wrap it in parentheses automatically.
    std::vector<std::string> processed;
    for (size_t i = 0; i < tokens.size(); ++i)
    {
        processed.push_back(tokens[i]);
        if (tokens[i] == "not" && i + 1 < tokens.size() && tokens[i + 1] != "(")
        {
            // Find the extent of the expression after "not":
            // It could be a single attribute token, or multiple tokens
            // connected by "and"/"or" until we hit a ")" or end.
            // For the simple case "not attr", wrap just the next token.
            // For compound cases, user should already use explicit parentheses.
            processed.push_back("(");
            processed.push_back(tokens[i + 1]);
            processed.push_back(")");
            ++i; // skip the next token as we already added it
        }
    }

    std::string result;
    for (const auto &t : processed)
    {
        if (!result.empty()) result += " ";
        result += t;
    }
    return result;
}

// Convert attributes from AC17 format to TKN20 format
// AC17: "admin it cs" (space-separated) → TKN20: "admin:admin,it:it,cs:cs"
static std::string convertAttrsToTKN20(const std::string &attrs)
{
    std::string lower = toLowerCase(attrs);
    std::istringstream iss(lower);
    std::string attr;
    std::string result;
    while (iss >> attr)
    {
        if (!result.empty()) result += ",";
        if (attr.find(':') != std::string::npos) {
            result += attr;
        } else {
            result += attr + ":" + attr;
        }
    }
    return result;
}

// ============================================================================
// TKN20 Setup
// ============================================================================

int tkn20_setup(const char *path)
{
    std::string strPath(path);
    try
    {
        CByteArray pubKey, msk;
        if (TKN20_Setup(&pubKey, &msk) != 0)
        {
            std::cerr << "TKN20 Setup failed: TKN20_Setup returned error." << std::endl;
            return HCPABE_ERR_CRYPTO_FAILED;
        }

        std::string mskPath, pkPath;
        struct stat info;
        if (stat(strPath.c_str(), &info) == 0 && (info.st_mode & S_IFDIR)) {
            mskPath = strPath + "/cpabe_msk.key";
            pkPath = strPath + "/cpabe_pk.key";
        } else if (strPath.empty() || strPath.back() == '/' || strPath.back() == '\\') {
            mskPath = strPath + "cpabe_msk.key";
            pkPath = strPath + "cpabe_pk.key";
        } else {
            mskPath = strPath + "_msk.key";
            pkPath = strPath + "_pk.key";
        }

        bool pkSaved = SaveBinaryAsBase64(pkPath, pubKey.data, pubKey.len);
        bool mskSaved = SaveBinaryAsBase64(mskPath, msk.data, msk.len);

        TKN20_FreeByteArray(pubKey);
        TKN20_FreeByteArray(msk);

        if (!pkSaved || !mskSaved)
        {
            std::cerr << "TKN20 Setup failed: Could not save key files." << std::endl;
            return HCPABE_ERR_FILE_NOT_FOUND;
        }

        std::cout << "TKN20 Setup completed successfully." << std::endl;
        return HCPABE_SUCCESS;
    }
    catch (const std::exception &ex)
    {
        std::cerr << "TKN20 Setup failed: " << ex.what() << std::endl;
        return HCPABE_ERR_CRYPTO_FAILED;
    }
}

int tkn20_setupBuffer(unsigned char **pkBuffer, size_t *pkLen, unsigned char **mskBuffer, size_t *mskLen)
{
    try
    {
        CByteArray pubKey, msk;
        if (TKN20_Setup(&pubKey, &msk) != 0)
        {
            return HCPABE_ERR_CRYPTO_FAILED;
        }

        *pkLen = pubKey.len;
        *pkBuffer = (unsigned char *)malloc(*pkLen);
        if (!*pkBuffer) return HCPABE_ERR_MEMORY;
        std::memcpy(*pkBuffer, pubKey.data, *pkLen);

        *mskLen = msk.len;
        *mskBuffer = (unsigned char *)malloc(*mskLen);
        if (!*mskBuffer) return HCPABE_ERR_MEMORY;
        std::memcpy(*mskBuffer, msk.data, *mskLen);

        TKN20_FreeByteArray(pubKey);
        TKN20_FreeByteArray(msk);

        return HCPABE_SUCCESS;
    }
    catch (...)
    {
        return HCPABE_ERR_CRYPTO_FAILED;
    }
}
// ============================================================================
// TKN20 KeyGen
// ============================================================================

int tkn20_genkey(const char *mskFile, const char *attrs, const char *skFile)
{
    try
    {
        // Load MSK (Base64 → binary)
        std::string mskDecoded;
        if (!LoadFile(mskFile, mskDecoded, "Base64"))
            return HCPABE_ERR_FILE_NOT_FOUND;

        // Convert attributes: AC17 format → TKN20 format
        std::string tkn20Attrs = convertAttrsToTKN20(attrs);

        CByteArray attrKeyOut;
        int res = TKN20_KeyGen(
            reinterpret_cast<uint8_t *>(const_cast<char *>(mskDecoded.data())),
            mskDecoded.size(),
            const_cast<char *>(tkn20Attrs.c_str()),
            &attrKeyOut);

        if (res != 0)
        {
            std::cerr << "TKN20 KeyGen failed." << std::endl;
            return HCPABE_ERR_CRYPTO_FAILED;
        }

        bool saved = SaveBinaryAsBase64(skFile, attrKeyOut.data, attrKeyOut.len);
        TKN20_FreeByteArray(attrKeyOut);

        if (!saved)
        {
            std::cerr << "TKN20: Failed to save private key file." << std::endl;
            return HCPABE_ERR_FILE_NOT_FOUND;
        }

        std::cout << "TKN20: Private key generated successfully." << std::endl;
        return HCPABE_SUCCESS;
    }
    catch (const std::exception &ex)
    {
        std::cerr << "TKN20 KeyGen error: " << ex.what() << std::endl;
        return HCPABE_ERR_CRYPTO_FAILED;
    }
}


int tkn20_genkeyBuffer(const unsigned char *mskBuffer, size_t mskLen, const char *attrs, unsigned char **skBuffer, size_t *skLen)
{
    try
    {
        std::string tkn20Attrs = convertAttrsToTKN20(attrs);

        CByteArray attrKeyOut;
        int res = TKN20_KeyGen(
            reinterpret_cast<uint8_t *>(const_cast<unsigned char *>(mskBuffer)),
            mskLen,
            const_cast<char *>(tkn20Attrs.c_str()),
            &attrKeyOut);

        if (res != 0) return HCPABE_ERR_CRYPTO_FAILED;

        *skLen = attrKeyOut.len;
        *skBuffer = (unsigned char *)malloc(*skLen);
        if (!*skBuffer) return HCPABE_ERR_MEMORY;
        std::memcpy(*skBuffer, attrKeyOut.data, *skLen);

        TKN20_FreeByteArray(attrKeyOut);
        return HCPABE_SUCCESS;
    }
    catch (...)
    {
        return HCPABE_ERR_CRYPTO_FAILED;
    }
}
// ============================================================================
// TKN20 Encapsulate Key
// ============================================================================

int tkn20_encapsulate_key(
    const unsigned char *pkData, size_t pkLen,
    const char *policy,
    const unsigned char *plaintext, size_t ptLen,
    unsigned char **ciphertext, size_t *ctLen)
{
    try
    {
        // Convert policy from AC17 format to TKN20 format
        std::string tkn20Policy = convertPolicyToTKN20(policy);

        CByteArray ctOut;
        int res = TKN20_Encrypt(
            const_cast<uint8_t *>(pkData), pkLen,
            const_cast<char *>(tkn20Policy.c_str()),
            const_cast<uint8_t *>(plaintext), ptLen,
            &ctOut);

        if (res != 0)
            return HCPABE_ERR_CRYPTO_FAILED;

        *ctLen = ctOut.len;
        *ciphertext = (unsigned char *)malloc(ctOut.len);
        if (!*ciphertext)
        {
            TKN20_FreeByteArray(ctOut);
            return HCPABE_ERR_MEMORY;
        }
        std::memcpy(*ciphertext, ctOut.data, ctOut.len);
        TKN20_FreeByteArray(ctOut);

        return HCPABE_SUCCESS;
    }
    catch (const std::exception &ex)
    {
        std::cerr << "TKN20 encrypt ABE key error: " << ex.what() << std::endl;
        return HCPABE_ERR_CRYPTO_FAILED;
    }
}

// ============================================================================
// TKN20 Decapsulate Key
// ============================================================================

int tkn20_decapsulate_key(
    const unsigned char *skData, size_t skLen,
    const unsigned char *ciphertext, size_t ctLen,
    unsigned char **plaintext, size_t *ptLen)
{
    try
    {
        CByteArray msgOut;
        int res = TKN20_Decrypt(
            const_cast<uint8_t *>(skData), skLen,
            const_cast<uint8_t *>(ciphertext), ctLen,
            &msgOut);

        if (res != 0)
            return HCPABE_ERR_POLICY_MISMATCH;

        *ptLen = msgOut.len;
        *plaintext = (unsigned char *)malloc(msgOut.len);
        if (!*plaintext)
        {
            TKN20_FreeByteArray(msgOut);
            return HCPABE_ERR_MEMORY;
        }
        std::memcpy(*plaintext, msgOut.data, msgOut.len);
        TKN20_FreeByteArray(msgOut);

        return HCPABE_SUCCESS;
    }
    catch (const std::exception &ex)
    {
        std::cerr << "TKN20 decrypt ABE key error: " << ex.what() << std::endl;
        return HCPABE_ERR_CRYPTO_FAILED;
    }
}

// ============================================================================
// TKN20 Load Keys (Base64-encoded binary files)
// ============================================================================

int tkn20_load_pk(const char *file, unsigned char **pkData, size_t *pkLen)
{
    try
    {
        std::string decoded;
        if (!LoadFile(file, decoded, "Base64"))
            return HCPABE_ERR_FILE_NOT_FOUND;

        *pkLen = decoded.size();
        *pkData = (unsigned char *)malloc(decoded.size());
        if (!*pkData)
            return HCPABE_ERR_MEMORY;
        std::memcpy(*pkData, decoded.data(), decoded.size());
        return HCPABE_SUCCESS;
    }
    catch (const std::exception &ex)
    {
        std::cerr << "TKN20 load PK error: " << ex.what() << std::endl;
        return HCPABE_ERR_FILE_NOT_FOUND;
    }
}

int tkn20_load_sk(const char *file, unsigned char **skData, size_t *skLen)
{
    try
    {
        std::string decoded;
        if (!LoadFile(file, decoded, "Base64"))
            return HCPABE_ERR_FILE_NOT_FOUND;

        *skLen = decoded.size();
        *skData = (unsigned char *)malloc(decoded.size());
        if (!*skData)
            return HCPABE_ERR_MEMORY;
        std::memcpy(*skData, decoded.data(), decoded.size());
        return HCPABE_SUCCESS;
    }
    catch (const std::exception &ex)
    {
        std::cerr << "TKN20 load SK error: " << ex.what() << std::endl;
        return HCPABE_ERR_FILE_NOT_FOUND;
    }
}

