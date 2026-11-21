#include "abe-internal.h"
#include "hybrid_pq_cp_abe/crypto-params.h"
#include <cryptopp/sha3.h>
#include <cryptopp/secblock.h>

// Project-owned protocol framing only; all primitives use existing backends.
namespace
{
    struct Failure
    {
        int code;
    };
    void require(bool value, int code = HCPABE_ERR_INVALID_PARAM)
    {
        if (!value)
            throw Failure{code};
    }
    void check(int code)
    {
        if (code != HCPABE_SUCCESS)
            throw Failure{code};
    }
    template <class F>
    int run(F operation)
    {
        try
        {
            operation();
            return HCPABE_SUCCESS;
        }
        catch (const Failure &e)
        {
            return e.code;
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
    struct Buffer
    {
        unsigned char *data = nullptr;
        size_t size = 0;
        Buffer() = default;
        Buffer(const Buffer &) = delete;
        Buffer &operator=(const Buffer &) = delete;
        ~Buffer()
        {
            if (data)
            {
                secureWipe(data, size);
                freeBuffer(data);
            }
        }
        void release(unsigned char **out, size_t *length)
        {
            *out = data;
            *length = size;
            data = nullptr;
            size = 0;
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
    bool outputs(std::initializer_list<std::pair<unsigned char **, size_t *>> values)
    {
        bool valid = true;
        for (auto a : values)
        {
            if (a.first)
                *a.first = nullptr;
            if (a.second)
                *a.second = 0;
            valid = valid && a.first && a.second;
        }
        for (auto a = values.begin(); a != values.end(); ++a)
            for (auto b = a + 1; b != values.end(); ++b)
                if (a->first == b->first || a->second == b->second)
                    valid = false;
        return valid;
    }
    bool scheme_valid(CPABEScheme scheme)
    {
        return scheme == CPABE_SCHEME_AC17 || scheme == CPABE_SCHEME_TKN20 || scheme == CPABE_SCHEME_COVERCRYPT;
    }
    int aes_bits(int bits)
    {
        bits = bits ? bits : 256;
        require(bits == 128 || bits == 192 || bits == 256);
        return bits;
    }
    int dsa_parameter(int parameter)
    {
        parameter = parameter ? parameter : 87;
        require(parameter == 44 || parameter == 65 || parameter == 87);
        return parameter;
    }
    void copy(const std::string &value, Buffer &buffer)
    {
        buffer.data = static_cast<unsigned char *>(std::malloc(value.empty() ? 1 : value.size()));
        require(buffer.data != nullptr, HCPABE_ERR_MEMORY);
        buffer.size = value.size();
        if (!value.empty())
            std::memcpy(buffer.data, value.data(), value.size());
    }
    void put_le(std::string &out, uint64_t value, size_t count)
    {
        for (size_t i = 0; i < count; ++i)
            out.push_back(static_cast<char>((value >> (8 * i)) & 255));
    }
    uint64_t get_le(const unsigned char *data, size_t count)
    {
        uint64_t value = 0;
        for (size_t i = 0; i < count; ++i)
            value |= uint64_t(data[i]) << (8 * i);
        return value;
    }
    std::string metadata(CPABEScheme scheme, int bits, int dsa)
    {
        std::string result;
        result.push_back(static_cast<char>(HybridCPABE::FORMAT_VERSION_3));
        result.push_back(static_cast<char>(scheme));
        result.push_back(static_cast<char>(bits / 8));
        result.push_back(static_cast<char>(dsa));
        return result;
    }
    std::string derive(const unsigned char *seed, size_t length, const std::string &meta)
    {
        CryptoPP::SHA3_256 hash;
        const std::string domain = "HCPABE-V3-AES";
        CryptoPP::SecByteBlock digest(hash.DigestSize());
        hash.Update(reinterpret_cast<const unsigned char *>(domain.data()), domain.size());
        hash.Update(reinterpret_cast<const unsigned char *>(meta.data()), meta.size());
        hash.Update(seed, length);
        hash.Final(digest);
        return std::string(reinterpret_cast<const char *>(digest.data()), static_cast<unsigned char>(meta[2]));
    }
    std::string signed_message(const std::string &meta, const std::string &body)
    {
        return std::string("HCPABE-V3-SIGN") + meta + body;
    }
    std::string base64(const Buffer &buffer)
    {
        std::string result;
        CryptoPP::StringSource(buffer.data, buffer.size, true,
                               new CryptoPP::Base64Encoder(new CryptoPP::StringSink(result), false));
        return result;
    }
    std::string decode(const unsigned char *data, size_t length)
    {
        require(data && length);
        std::string result;
        CryptoPP::StringSource(data, length, true,
                               new CryptoPP::Base64Decoder(new CryptoPP::StringSink(result)));
        return result;
    }
    void encapsulate(CPABEScheme scheme, const unsigned char *pk, size_t pk_len,
                     const char *policy, const unsigned char *seed, size_t seed_len, Buffer &out)
    {
        switch (scheme)
        {
        case CPABE_SCHEME_AC17:
            check(ac17_encapsulate_key(pk, pk_len, policy, seed, seed_len, &out.data, &out.size));
            break;
        case CPABE_SCHEME_TKN20:
            check(tkn20_encapsulate_key(pk, pk_len, policy, seed, seed_len, &out.data, &out.size));
            break;
        case CPABE_SCHEME_COVERCRYPT:
            check(covercrypt_encapsulate_key(pk, pk_len, policy, seed, seed_len, &out.data, &out.size));
            break;
        default:
            throw Failure{HCPABE_ERR_INVALID_PARAM};
        }
    }
    void decapsulate(CPABEScheme scheme, const unsigned char *sk, size_t sk_len,
                     const unsigned char *ct, size_t ct_len, Buffer &out)
    {
        switch (scheme)
        {
        case CPABE_SCHEME_AC17:
            check(ac17_decapsulate_key(sk, sk_len, ct, ct_len, &out.data, &out.size));
            break;
        case CPABE_SCHEME_TKN20:
            check(tkn20_decapsulate_key(sk, sk_len, ct, ct_len, &out.data, &out.size));
            break;
        case CPABE_SCHEME_COVERCRYPT:
            check(covercrypt_decapsulate_key(sk, sk_len, ct, ct_len, &out.data, &out.size));
            break;
        default:
            throw Failure{HCPABE_ERR_INVALID_PARAM};
        }
    }
    void encrypt(CPABEScheme scheme, int bits, int dsa,
                 const unsigned char *pk, size_t pk_len, const unsigned char *pt, size_t pt_len,
                 const char *policy, Buffer &out)
    {
        const auto meta = metadata(scheme, bits, dsa);
        CryptoPP::AutoSeededRandomPool rng;
        CryptoPP::SecByteBlock seed(32), iv(HybridCPABE::GCM_IV_SIZE);
        rng.GenerateBlock(seed, seed.size());
        rng.GenerateBlock(iv, iv.size());
        Buffer encapsulation, encrypted;
        encapsulate(scheme, pk, pk_len, policy, seed, seed.size(), encapsulation);
        std::string aad = meta;
        aad.append(reinterpret_cast<const char *>(iv.data()), iv.size());
        put_le(aad, encapsulation.size, 8);
        aad.append(reinterpret_cast<const char *>(encapsulation.data), encapsulation.size);
        auto key = derive(seed, seed.size(), meta);
        Wipe wipe_key{key};
        check(aes_gcm_encrypt(reinterpret_cast<const unsigned char *>(key.data()), key.size(), iv, iv.size(),
                              pt, pt_len, reinterpret_cast<const unsigned char *>(aad.data()), aad.size(), &encrypted.data, &encrypted.size));
        aad.append(reinterpret_cast<const char *>(encrypted.data), encrypted.size);
        copy(aad, out);
    }
    void read_file(const char *path, std::string &result, const char *format)
    {
        require(path);
        require(LoadFile(path, result, format), HCPABE_ERR_FILE_NOT_FOUND);
    }
    void write_file(const char *path, const Buffer &value)
    {
        require(path);
        std::ofstream file(path, std::ios::binary | std::ios::trunc);
        require(bool(file), HCPABE_ERR_FILE_NOT_FOUND);
        if (value.size)
            file.write(reinterpret_cast<const char *>(value.data), value.size);
        file.close();
        require(bool(file), HCPABE_ERR_FILE_NOT_FOUND);
    }
}

extern "C"
{
    int hybrid_cpabe_covercrypt_ml_kem_parameter_set(void) { return 768; }

    int hybrid_cpabe_encryptBuffer_with_params(const unsigned char *pk, size_t pk_len,
                                               const unsigned char *pt, size_t pt_len, const char *policy,
                                               unsigned char **ct, size_t *ct_len, CPABEScheme scheme, int bits)
    {
        if (!outputs({{ct, ct_len}}))
            return HCPABE_ERR_INVALID_PARAM;
        return run([&]
                   {
        require(pk && pk_len && (pt || !pt_len) && policy && scheme_valid(scheme));
        Buffer result;
        encrypt(scheme, aes_bits(bits), 0, pk, pk_len, pt, pt_len, policy, result);
        result.release(ct, ct_len); });
    }

    int hybrid_cpabe_encryptBuffer_and_sign_with_params(const unsigned char *pk, size_t pk_len,
                                                        const unsigned char *signing_key, size_t signing_key_len, const unsigned char *pt, size_t pt_len,
                                                        const char *policy, unsigned char **ct, size_t *ct_len, CPABEScheme scheme, int bits, int parameter)
    {
        if (!outputs({{ct, ct_len}}))
            return HCPABE_ERR_INVALID_PARAM;
        return run([&]
                   {
        require(pk && pk_len && (pt || !pt_len) && policy && signing_key && signing_key_len && scheme_valid(scheme));
        bits = aes_bits(bits); parameter = dsa_parameter(parameter);
        auto raw_key = decode(signing_key, signing_key_len);
        Wipe wipe_key{raw_key};
        const size_t policy_len = std::strlen(policy);
        require(policy_len <= UINT32_MAX);
        std::string body;
        Wipe wipe_body{body};
        put_le(body, policy_len, 4);
        body.append(policy, policy_len);
        if (pt_len) body.append(reinterpret_cast<const char *>(pt), pt_len);
        auto message = signed_message(metadata(scheme, bits, parameter), body);
        Wipe wipe_message{message};
        Buffer signature, result;
        check(ml_dsa_sign(parameter, reinterpret_cast<const unsigned char *>(message.data()), message.size(),
            reinterpret_cast<const unsigned char *>(raw_key.data()), raw_key.size(), &signature.data, &signature.size));
        std::string payload;
        Wipe wipe_payload{payload};
        put_le(payload, signature.size, 4);
        payload.append(reinterpret_cast<const char *>(signature.data), signature.size);
        payload.append(body);
        encrypt(scheme, bits, parameter, pk, pk_len, reinterpret_cast<const unsigned char *>(payload.data()),
            payload.size(), policy, result);
        result.release(ct, ct_len); });
    }

    int hybrid_cpabe_encrypt_with_params(const char *pk_path, const char *pt_path, const char *policy,
                                         const char *ct_path, CPABEScheme scheme, int bits)
    {
        return run([&]
                   {
        require(policy && ct_path && scheme_valid(scheme));
        bits = aes_bits(bits);
        std::string pk, pt;
        Wipe wipe{pt};
        read_file(pk_path, pk, "Base64"); read_file(pt_path, pt, "Original");
        Buffer result;
        check(hybrid_cpabe_encryptBuffer_with_params(reinterpret_cast<const unsigned char *>(pk.data()), pk.size(),
            reinterpret_cast<const unsigned char *>(pt.data()), pt.size(), policy, &result.data, &result.size, scheme, bits));
        write_file(ct_path, result); });
    }

    int hybrid_cpabe_encrypt_and_sign_with_params(const char *pk_path, const char *sign_path,
                                                  const char *pt_path, const char *policy, const char *ct_path, CPABEScheme scheme, int bits, int parameter)
    {
        return run([&]
                   {
        require(policy && ct_path && scheme_valid(scheme));
        bits = aes_bits(bits); parameter = dsa_parameter(parameter);
        std::string pk, sk, pt;
        Wipe wipe_sk{sk}, wipe_pt{pt};
        read_file(pk_path, pk, "Base64"); read_file(sign_path, sk, "Base64"); read_file(pt_path, pt, "Original");
        Buffer result;
        check(hybrid_cpabe_encryptBuffer_and_sign_with_params(reinterpret_cast<const unsigned char *>(pk.data()), pk.size(),
            reinterpret_cast<const unsigned char *>(sk.data()), sk.size(),
            reinterpret_cast<const unsigned char *>(pt.data()), pt.size(), policy, &result.data, &result.size, scheme, bits, parameter));
        write_file(ct_path, result); });
    }

    int hybrid_cpabe_setupBuffer_with_ml_dsa(unsigned char **pk, size_t *pk_len,
                                                 unsigned char **msk, size_t *msk_len, unsigned char **verify, size_t *verify_len,
                                                 unsigned char **sign, size_t *sign_len, CPABEScheme scheme, int parameter)
    {
        if (!outputs({{pk, pk_len}, {msk, msk_len}, {verify, verify_len}, {sign, sign_len}}))
            return HCPABE_ERR_INVALID_PARAM;
        return run([&]
                   {
        require(scheme_valid(scheme)); parameter = dsa_parameter(parameter);
        Buffer abe_pk, abe_msk, sig_pk, sig_sk, encoded_pk, encoded_sk;
        check(hybrid_cpabe_setupBuffer_with_scheme(&abe_pk.data, &abe_pk.size, &abe_msk.data, &abe_msk.size, scheme));
        check(ml_dsa_generate_keypair(parameter, &sig_pk.data, &sig_pk.size, &sig_sk.data, &sig_sk.size));
        copy(base64(sig_pk), encoded_pk);
        auto encoded = base64(sig_sk);
        Wipe wipe{encoded};
        copy(encoded, encoded_sk);
        abe_pk.release(pk, pk_len); abe_msk.release(msk, msk_len);
        encoded_pk.release(verify, verify_len); encoded_sk.release(sign, sign_len); });
    }

    int hybrid_cpabe_setup_with_ml_dsa(const char *path, CPABEScheme scheme, int parameter)
    {
        return setup_with_ml_dsa_files(path, scheme, parameter, "pqc");
    }

    int hybrid_cpabe_setup_with_signing_keys(const char *path, CPABEScheme scheme, int parameter)
    {
        return setup_with_ml_dsa_files(path, scheme, parameter, "ml-dsa");
    }
}

int setup_with_ml_dsa_files(const char *path, CPABEScheme scheme, int parameter, const char *key_label)
{
    return run([&]
               {
        require(path && scheme_valid(scheme)); parameter = dsa_parameter(parameter);
        Buffer pk, sk;
        check(ml_dsa_generate_keypair(parameter, &pk.data, &pk.size, &sk.data, &sk.size));
        check(setup_with_scheme(path, scheme));
        std::string prefix(path);
        struct stat info;
        if ((stat(path, &info) == 0 && (info.st_mode & S_IFDIR)) ||
            (!prefix.empty() && (prefix.back() == '/' || prefix.back() == '\\'))) {
            if (!prefix.empty() && prefix.back() != '/' && prefix.back() != '\\') prefix += '/';
        } else if (!prefix.empty()) prefix += '_';
        auto public_key = base64(pk), secret_key = base64(sk);
        Wipe wipe{secret_key};
        prefix += key_label;
        require(SaveFile(prefix + "_pk.key", public_key.c_str(), "Base64"), HCPABE_ERR_FILE_NOT_FOUND);
        require(SaveFile(prefix + "_sk.key", secret_key.c_str(), "Base64"), HCPABE_ERR_FILE_NOT_FOUND); });
}

int hybrid_cpabe_decrypt_v3(const unsigned char *sk, size_t sk_len,
                            const unsigned char *verify_key, size_t verify_key_len, const unsigned char *ct, size_t ct_len,
                            unsigned char **pt, size_t *pt_len, bool verify)
{
    if (!outputs({{pt, pt_len}}))
        return HCPABE_ERR_INVALID_PARAM;
    return run([&]
               {
        require(sk && sk_len && ct && ct_len >= 24 + 16);
        require(ct[0] == HybridCPABE::FORMAT_VERSION_3, HCPABE_ERR_VERSION_MISMATCH);
        const auto scheme = static_cast<CPABEScheme>(ct[1]);
        const int key_bytes = ct[2], parameter = ct[3];
        require(scheme_valid(scheme) && (key_bytes == 16 || key_bytes == 24 || key_bytes == 32));
        require(parameter == 0 || parameter == 44 || parameter == 65 || parameter == 87);
        if (verify) require(parameter != 0 && verify_key && verify_key_len, HCPABE_ERR_SIGNATURE_INVALID);
        const uint64_t encapsulation_len = get_le(ct + 16, 8);
        require(encapsulation_len && encapsulation_len <= ct_len - 24 - 16, HCPABE_ERR_CRYPTO_FAILED);
        const size_t aad_len = 24 + static_cast<size_t>(encapsulation_len);
        Buffer seed, recovered, result;
        decapsulate(scheme, sk, sk_len, ct + 24, static_cast<size_t>(encapsulation_len), seed);
        require(seed.size == 32, HCPABE_ERR_INVALID_KEY);
        const std::string meta(reinterpret_cast<const char *>(ct), 4);
        auto key = derive(seed.data, seed.size, meta);
        Wipe wipe_key{key};
        check(aes_gcm_decrypt(reinterpret_cast<const unsigned char *>(key.data()), key.size(), ct + 4, 12,
            ct + aad_len, ct_len - aad_len, ct, aad_len, &recovered.data, &recovered.size));
        if (!verify) { recovered.release(pt, pt_len); return; }
        require(recovered.size >= 4, HCPABE_ERR_CRYPTO_FAILED);
        const size_t sig_len = static_cast<size_t>(get_le(recovered.data, 4));
        require(sig_len <= recovered.size - 4, HCPABE_ERR_CRYPTO_FAILED);
        const size_t body_offset = 4 + sig_len;
        const auto body_size = recovered.size - body_offset;
        require(body_size >= 4, HCPABE_ERR_CRYPTO_FAILED);
        const size_t policy_len = static_cast<size_t>(get_le(recovered.data + body_offset, 4));
        require(policy_len <= body_size - 4, HCPABE_ERR_CRYPTO_FAILED);
        auto raw_key = decode(verify_key, verify_key_len);
        auto message = signed_message(meta, std::string(reinterpret_cast<const char *>(recovered.data + body_offset), body_size));
        Wipe wipe_message{message};
        check(ml_dsa_verify(parameter, reinterpret_cast<const unsigned char *>(message.data()), message.size(),
            recovered.data + 4, sig_len, reinterpret_cast<const unsigned char *>(raw_key.data()), raw_key.size()));
        const auto payload_offset = body_offset + 4 + policy_len;
        copy(std::string(reinterpret_cast<const char *>(recovered.data + payload_offset), recovered.size - payload_offset), result);
        result.release(pt, pt_len); });
}
