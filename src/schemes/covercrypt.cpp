#include "hybrid_pq_cp_abe/cpabe-scheme.h"
#include "hybrid_pq_cp_abe/hybrid-pq-cp-abe.h"
#include "hybrid_pq_cp_abe/common-utils.h"
#include <covercrypt/covercrypt_ffi.h>
#include <cryptopp/osrng.h>
#include <cctype>
#include <cstdlib>
#include <limits>
#include <memory>
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#endif

namespace
{
using Bytes = std::vector<unsigned char>;
using Allocation = std::unique_ptr<unsigned char, decltype(&std::free)>;
struct Error
{
    int code;
};
struct Buffer
{
    cc_buffer value{nullptr, 0};
    Buffer() = default;
    Buffer(const Buffer &) = delete;
    Buffer &operator=(const Buffer &) = delete;
    ~Buffer()
    {
        cc_buffer_free(&value);
    }
};
struct Wipe
{
    std::string &value;
    ~Wipe()
    {
        if (!value.empty())
            secureWipe(&value[0], value.size());
    }
};
template <class Operation> int run(Operation operation)
{
    try
    {
        operation();
        return HCPABE_SUCCESS;
    }
    catch (const Error &error)
    {
        return error.code;
    }
    catch (const std::bad_alloc &)
    {
        return HCPABE_ERR_MEMORY;
    }
    catch (...)
    {
        return HCPABE_ERR_CRYPTO_FAILED;
    }
}
void check(int status)
{
    if (status == CC_OK)
        return;
    if (status == CC_INVALID_INPUT)
        throw Error{HCPABE_ERR_INVALID_PARAM};
    if (status == CC_ACCESS_DENIED)
        throw Error{HCPABE_ERR_POLICY_MISMATCH};
    throw Error{HCPABE_ERR_CRYPTO_FAILED};
}
Allocation copy(const unsigned char *data, size_t length)
{
    Allocation output(static_cast<unsigned char *>(std::malloc(length ? length : 1)), &std::free);
    if (!output)
        throw std::bad_alloc();
    if (length)
        std::memcpy(output.get(), data, length);
    return output;
}
void output(const unsigned char *data, size_t length, unsigned char **buffer, size_t *size)
{
    auto allocation = copy(data, length);
    *size = length;
    *buffer = allocation.release();
}
// Bare v5.2 attributes use boolean dimensions, e.g. admin::{present,absent}.
std::string normalize_policy(const std::string &input, bool attribute_list = false)
{
    std::string result;
    bool previous_atom = false;
    for (size_t position = 0; position < input.size();)
    {
        unsigned char ch = static_cast<unsigned char>(input[position]);
        if (std::isspace(ch))
        {
            ++position;
            continue;
        }
        if (ch == '(' || ch == ')')
        {
            result += static_cast<char>(ch);
            ++position;
            previous_atom = ch == ')';
            continue;
        }
        bool quoted = ch == '"' || ch == '\'';
        std::string token;
        if (quoted)
        {
            char quote = input[position++];
            size_t end = input.find(quote, position);
            if (end == std::string::npos)
                throw Error{HCPABE_ERR_INVALID_PARAM};
            token = input.substr(position, end - position);
            position = end + 1;
        }
        else if (ch == '&' || ch == '|')
        {
            if (position + 1 >= input.size() || input[position + 1] != ch)
                throw Error{HCPABE_ERR_INVALID_PARAM};
            token = input.substr(position, 2);
            position += 2;
        }
        else
        {
            size_t start = position;
            while (position < input.size() && !std::isspace(static_cast<unsigned char>(input[position])) &&
                   input[position] != '(' && input[position] != ')' && input[position] != '&' && input[position] != '|')
                ++position;
            token = input.substr(start, position - start);
        }
        std::string lowered = toLowerCase(token);
        if (!quoted && (lowered == "and" || token == "&&" || lowered == "or" || token == "||"))
        {
            result += (lowered == "and" || token == "&&") ? " && " : " || ";
            previous_atom = false;
        }
        else
        {
            if ((!quoted && lowered == "not") || token.empty())
                throw Error{HCPABE_ERR_INVALID_PARAM};
            if (attribute_list && previous_atom)
                result += " && ";
            result += token.find("::") == std::string::npos ? lowered + "::present" : token;
            previous_atom = true;
        }
    }
    return result;
}
int load_key(const char *file, unsigned char **data, size_t *length)
{
    if (!file || !data || !length)
        return HCPABE_ERR_INVALID_PARAM;
    *data = nullptr;
    *length = 0;
    return run([&] {
        std::string raw;
        Wipe wipe{raw};
        if (!LoadFile(file, raw, "Base64"))
            throw Error{HCPABE_ERR_FILE_NOT_FOUND};
        output(reinterpret_cast<const unsigned char *>(raw.data()), raw.size(), data, length);
    });
}

int configured_mode()
{
    const char *value = std::getenv("HCPABE_COVERCRYPT_MODE");
    if (!value)
        return CC_HYBRIDIZED;
    const std::string choice = toLowerCase(value);
    if (choice == "hybridized") return CC_HYBRIDIZED;
    if (choice == "classic") return CC_CLASSIC;
    if (choice == "post_quantum") return CC_POST_QUANTUM;
    throw Error{HCPABE_ERR_INVALID_PARAM};
}

template <class Operation>
int grow_buffer(const unsigned char *msk, size_t mskLen, unsigned char **pkOut, size_t *pkLen,
                unsigned char **mskOut, size_t *mskOutLen, Operation operation)
{
    if (!pkOut || !pkLen || !mskOut || !mskOutLen || pkOut == mskOut || pkLen == mskOutLen)
        return HCPABE_ERR_INVALID_PARAM;
    *pkOut = nullptr; *pkLen = 0; *mskOut = nullptr; *mskOutLen = 0;
    if (!msk || !mskLen)
        return HCPABE_ERR_INVALID_PARAM;
    return run([&] {
        Buffer secret, public_key;
        check(operation(&secret.value, &public_key.value));
        auto pk = copy(public_key.value.data, public_key.value.len);
        auto master = copy(secret.value.data, secret.value.len);
        *pkLen = public_key.value.len; *mskOutLen = secret.value.len;
        *pkOut = pk.release(); *mskOut = master.release();
    });
}

struct SensitiveAllocation
{
    unsigned char *data = nullptr;
    size_t length = 0;
    ~SensitiveAllocation()
    {
        if (data) secureWipe(data, length);
        std::free(data);
    }
};

template <class Operation>
int grow_file(const char *mskFile, const char *outPrefix, Operation operation)
{
    if (!mskFile || !outPrefix || !*outPrefix)
        return HCPABE_ERR_INVALID_PARAM;
    return run([&] {
        std::string prefix(outPrefix);
        struct stat info;
        bool directory = (stat(outPrefix, &info) == 0 && (info.st_mode & S_IFDIR)) ||
                         prefix.back() == '/' || prefix.back() == '\\';
        if (directory && prefix.back() != '/' && prefix.back() != '\\') prefix += '/';
        const std::string pkFile = prefix + (directory ? "cpabe_pk.key" : "_pk.key");
        const std::string masterFile = prefix + (directory ? "cpabe_msk.key" : "_msk.key");
        // Publish a separate updated pair, never overwrite the input authority.
        if (stat(pkFile.c_str(), &info) == 0 || stat(masterFile.c_str(), &info) == 0)
            throw Error{HCPABE_ERR_INVALID_PARAM};
        std::string raw;
        Wipe wipe{raw};
        if (!LoadFile(mskFile, raw, "Base64")) throw Error{HCPABE_ERR_FILE_NOT_FOUND};
        unsigned char *publicData = nullptr;
        size_t publicLen = 0;
        SensitiveAllocation master;
        int status = operation(reinterpret_cast<const unsigned char *>(raw.data()), raw.size(),
                               &publicData, &publicLen, &master.data, &master.length);
        Allocation pk(publicData, &std::free);
        if (status != HCPABE_SUCCESS) throw Error{status};
        if (!SaveBinaryAsBase64(masterFile, master.data, master.length)) {
            std::remove(masterFile.c_str());
            throw Error{HCPABE_ERR_FILE_NOT_FOUND};
        }
        if (!SaveBinaryAsBase64(pkFile, publicData, publicLen)) {
            std::remove(masterFile.c_str());
            std::remove(pkFile.c_str());
            throw Error{HCPABE_ERR_FILE_NOT_FOUND};
        }
    });
}
} // namespace

int covercrypt_setupBuffer(unsigned char **pkBuffer, size_t *pkLen, unsigned char **mskBuffer, size_t *mskLen)
{
    if (!pkBuffer || !pkLen || !mskBuffer || !mskLen || pkBuffer == mskBuffer || pkLen == mskLen)
        return HCPABE_ERR_INVALID_PARAM;
    *pkBuffer = nullptr;
    *pkLen = 0;
    *mskBuffer = nullptr;
    *mskLen = 0;
    return run([&] {
        const char *configuration = std::getenv("HCPABE_COVERCRYPT_CONFIG");
        if (!configuration || !*configuration)
            throw Error{HCPABE_ERR_INVALID_PARAM};
        std::string json;
        if (!LoadFile(configuration, json, "Original"))
            throw Error{HCPABE_ERR_FILE_NOT_FOUND};
        int mode = configured_mode();
        Buffer secret, public_key;
        check(cc_setup(json.c_str(), mode, &secret.value, &public_key.value));
        auto pk = copy(public_key.value.data, public_key.value.len);
        auto msk = copy(secret.value.data, secret.value.len);
        *pkLen = public_key.value.len;
        *mskLen = secret.value.len;
        *pkBuffer = pk.release();
        *mskBuffer = msk.release();
    });
}

int covercrypt_setup(const char *path)
{
    if (!path)
        return HCPABE_ERR_INVALID_PARAM;
    return run([&] {
        unsigned char *pk = nullptr, *msk = nullptr;
        size_t pkLen = 0, mskLen = 0;
        int status = covercrypt_setupBuffer(&pk, &pkLen, &msk, &mskLen);
        Allocation publicKey(pk, &std::free), masterKey(msk, &std::free);
        if (status != HCPABE_SUCCESS)
            throw Error{status};
        std::string prefix(path);
        struct stat info;
        bool directory = (stat(path, &info) == 0 && (info.st_mode & S_IFDIR)) || prefix.empty() ||
                         prefix.back() == '/' || prefix.back() == '\\';
        if (directory && !prefix.empty() && prefix.back() != '/' && prefix.back() != '\\')
            prefix += '/';
        auto pkFile = prefix + (directory ? "cpabe_pk.key" : "_pk.key");
        auto mskFile = prefix + (directory ? "cpabe_msk.key" : "_msk.key");
        bool saved = SaveBinaryAsBase64(pkFile, pk, pkLen) && SaveBinaryAsBase64(mskFile, msk, mskLen);
        secureWipe(msk, mskLen);
        if (!saved)
            throw Error{HCPABE_ERR_FILE_NOT_FOUND};
    });
}

int covercrypt_genkeyBuffer(const unsigned char *mskBuffer, size_t mskLen, const char *attrs, unsigned char **skBuffer,
                            size_t *skLen)
{
    if (!skBuffer || !skLen)
        return HCPABE_ERR_INVALID_PARAM;
    *skBuffer = nullptr;
    *skLen = 0;
    if (!mskBuffer || !mskLen || !attrs)
        return HCPABE_ERR_INVALID_PARAM;
    return run([&] {
        Buffer user;
        auto policy = normalize_policy(attrs, true);
        check(cc_genkey_ephemeral(mskBuffer, mskLen, policy.c_str(), &user.value));
        // As in v5.2, the buffer interface is stateless. Tracing registration is
        // retained by file-based genkey; no tracing operations are exposed by this API.
        output(user.value.data, user.value.len, skBuffer, skLen);
    });
}

int covercrypt_genkey(const char *mskFile, const char *attrs, const char *skFile)
{
    if (!mskFile || !attrs || !skFile || std::strcmp(mskFile, skFile) == 0)
        return HCPABE_ERR_INVALID_PARAM;
    return run([&] {
        std::string raw;
        Wipe wipe{raw};
        if (!LoadFile(mskFile, raw, "Base64"))
            throw Error{HCPABE_ERR_FILE_NOT_FOUND};
        Buffer updated, user;
        auto policy = normalize_policy(attrs, true);
        check(cc_genkey(reinterpret_cast<const unsigned char *>(raw.data()), raw.size(), policy.c_str(), &updated.value,
                        &user.value));
        unsigned char suffix[16];
        CryptoPP::AutoSeededRandomPool rng;
        rng.GenerateBlock(suffix, sizeof(suffix));
        const char hex[] = "0123456789abcdef";
        std::string temporary = std::string(mskFile) + ".tmp.";
        for (auto byte : suffix)
        {
            temporary += hex[byte >> 4];
            temporary += hex[byte & 15];
        }
        if (!SaveBinaryAsBase64(temporary, updated.value.data, updated.value.len))
        {
            std::remove(temporary.c_str());
            throw Error{HCPABE_ERR_FILE_NOT_FOUND};
        }
#ifdef _WIN32
        bool committed =
            MoveFileExA(temporary.c_str(), mskFile, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) != 0;
#else
        bool committed = std::rename(temporary.c_str(), mskFile) == 0;
#endif
        if (!committed)
        {
            std::remove(temporary.c_str());
            throw Error{HCPABE_ERR_FILE_NOT_FOUND};
        }
        if (!SaveBinaryAsBase64(skFile, user.value.data, user.value.len))
            throw Error{HCPABE_ERR_FILE_NOT_FOUND};
    });
}

// Match the existing scheme contract: protect a supplied key buffer. CoverCrypt
// provides a KEM secret, which AES-GCM uses to wrap that buffer inside the adapter.
int covercrypt_encapsulate_key(const unsigned char *pkData, size_t pkLen, const char *policy,
                               const unsigned char *plaintext, size_t ptLen, unsigned char **ciphertext, size_t *ctLen)
{
    if (!ciphertext || !ctLen)
        return HCPABE_ERR_INVALID_PARAM;
    *ciphertext = nullptr;
    *ctLen = 0;
    if (!pkData || !pkLen || !policy || (!plaintext && ptLen))
        return HCPABE_ERR_INVALID_PARAM;
    return run([&] {
        Buffer secret, encapsulation;
        auto normalized = normalize_policy(policy);
        check(cc_encaps(pkData, pkLen, normalized.c_str(), &secret.value, &encapsulation.value));
        if (secret.value.len != 32 || encapsulation.value.len > std::numeric_limits<uint32_t>::max())
            throw Error{HCPABE_ERR_CRYPTO_FAILED};
        Bytes frame{'K', 'C', 'C', 1};
        for (int shift = 24; shift >= 0; shift -= 8)
            frame.push_back(static_cast<unsigned char>((encapsulation.value.len >> shift) & 255));
        frame.resize(20);
        CryptoPP::AutoSeededRandomPool rng;
        rng.GenerateBlock(frame.data() + 8, 12);
        frame.insert(frame.end(), encapsulation.value.data, encapsulation.value.data + encapsulation.value.len);
        unsigned char *raw = nullptr;
        size_t length = 0;
        int status = aes_gcm_encrypt(secret.value.data, secret.value.len, frame.data() + 8, 12, plaintext, ptLen,
                                     frame.data(), frame.size(), &raw, &length);
        Allocation sealed(raw, &std::free);
        if (status != HCPABE_SUCCESS)
            throw Error{status};
        frame.insert(frame.end(), raw, raw + length);
        output(frame.data(), frame.size(), ciphertext, ctLen);
    });
}

int covercrypt_decapsulate_key(const unsigned char *skData, size_t skLen, const unsigned char *ciphertext, size_t ctLen,
                               unsigned char **plaintext, size_t *ptLen)
{
    if (!plaintext || !ptLen)
        return HCPABE_ERR_INVALID_PARAM;
    *plaintext = nullptr;
    *ptLen = 0;
    if (!skData || !skLen || !ciphertext)
        return HCPABE_ERR_INVALID_PARAM;
    return run([&] {
        const unsigned char magic[] = {'K', 'C', 'C', 1};
        if (ctLen < 37 || std::memcmp(ciphertext, magic, sizeof(magic)))
            throw Error{HCPABE_ERR_UNSUPPORTED_FORMAT};
        size_t length = 0;
        for (size_t i = 4; i < 8; ++i)
            length = (length << 8) | ciphertext[i];
        if (!length || length > ctLen - 20 - 16)
            throw Error{HCPABE_ERR_UNSUPPORTED_FORMAT};
        Buffer secret;
        check(cc_decaps(skData, skLen, ciphertext + 20, length, &secret.value));
        if (secret.value.len != 32)
            throw Error{HCPABE_ERR_CRYPTO_FAILED};
        unsigned char *raw = nullptr;
        size_t recoveredLen = 0;
        int status = aes_gcm_decrypt(secret.value.data, secret.value.len, ciphertext + 8, 12, ciphertext + 20 + length,
                                     ctLen - 20 - length, ciphertext, 20 + length, &raw, &recoveredLen);
        Allocation recovered(raw, &std::free);
        if (status != HCPABE_SUCCESS)
            throw Error{status};
        *ptLen = recoveredLen;
        *plaintext = recovered.release();
    });
}

int covercrypt_load_pk(const char *file, unsigned char **pkData, size_t *pkLen)
{
    return load_key(file, pkData, pkLen);
}

int covercrypt_load_sk(const char *file, unsigned char **skData, size_t *skLen)
{
    return load_key(file, skData, skLen);
}

int covercrypt_add_attributeBuffer(const unsigned char *msk, size_t mskLen, const char *dimension,
    const char *attribute, const char *after, unsigned char **pkOut, size_t *pkLen,
    unsigned char **mskOut, size_t *mskOutLen)
{
    return grow_buffer(msk, mskLen, pkOut, pkLen, mskOut, mskOutLen, [&](cc_buffer *secret, cc_buffer *pub) {
        return cc_add_attribute(msk, mskLen, dimension, attribute, configured_mode(), after, secret, pub);
    });
}

int covercrypt_add_dimensionBuffer(const unsigned char *msk, size_t mskLen, const char *json,
    unsigned char **pkOut, size_t *pkLen, unsigned char **mskOut, size_t *mskOutLen)
{
    return grow_buffer(msk, mskLen, pkOut, pkLen, mskOut, mskOutLen, [&](cc_buffer *secret, cc_buffer *pub) {
        return cc_add_dimension(msk, mskLen, json, configured_mode(), secret, pub);
    });
}

int covercrypt_add_attribute(const char *mskFile, const char *dimension, const char *attribute,
    const char *after, const char *outPrefix)
{
    return grow_file(mskFile, outPrefix, [&](const unsigned char *msk, size_t len,
        unsigned char **pk, size_t *pkLen, unsigned char **master, size_t *masterLen) {
        return covercrypt_add_attributeBuffer(msk, len, dimension, attribute, after, pk, pkLen, master, masterLen);
    });
}

int covercrypt_add_dimension(const char *mskFile, const char *json, const char *outPrefix)
{
    return grow_file(mskFile, outPrefix, [&](const unsigned char *msk, size_t len,
        unsigned char **pk, size_t *pkLen, unsigned char **master, size_t *masterLen) {
        return covercrypt_add_dimensionBuffer(msk, len, json, pk, pkLen, master, masterLen);
    });
}
