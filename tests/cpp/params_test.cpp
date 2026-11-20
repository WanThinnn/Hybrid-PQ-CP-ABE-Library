#include "hybrid_pq_cp_abe/crypto-params.h"
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
struct Buffer {
    unsigned char *data = nullptr; size_t size = 0;
    ~Buffer() { freeBuffer(data); }
};
void require(bool ok, const char *message) { if (!ok) throw std::runtime_error(message); }
void success(int code) { require(code == 0, getErrorMessage(code)); }
void same(const Buffer &value, const std::string &expected) {
    require(value.size == expected.size() && (!value.size || !std::memcmp(value.data, expected.data(), value.size)), "payload mismatch");
}
void rejected(int status, const Buffer &value) {
    require(status != 0 && value.data == nullptr && value.size == 0, "failure leaked plaintext/output");
}
void environment(const char *name, const char *value) {
#ifdef _WIN32
    require(_putenv_s(name, value) == 0, "environment failed");
#else
    require(setenv(name, value, 1) == 0, "environment failed");
#endif
}
void check_primitives() {
    const unsigned char message[] = {0, 1, 127, 255}, nonce[12] = {}, aad[] = {1};
    for (int bits : {128, 192, 256}) {
        Buffer key, ct, pt, invalid;
        success(aes_gcm_generate_key(bits, &key.data, &key.size));
        require(key.size == size_t(bits / 8), "wrong AES key size");
        success(aes_gcm_encrypt(key.data, key.size, nonce, sizeof(nonce), message, sizeof(message), aad, sizeof(aad), &ct.data, &ct.size));
        success(aes_gcm_decrypt(key.data, key.size, nonce, sizeof(nonce), ct.data, ct.size, aad, sizeof(aad), &pt.data, &pt.size));
        same(pt, std::string(reinterpret_cast<const char *>(message), sizeof(message)));
        rejected(aes_gcm_decrypt(key.data, key.size, nonce, sizeof(nonce), ct.data, ct.size, nullptr, 0, &invalid.data, &invalid.size), invalid);
        rejected(aes_gcm_encrypt(key.data, key.size - 1, nonce, sizeof(nonce), message, sizeof(message), nullptr, 0, &invalid.data, &invalid.size), invalid);
    }
    // Published AES-GCM zero-key/zero-IV empty-message vector (Crypto++ gcm.txt).
    const unsigned char zero_key[16] = {}, tag[] = {0x58,0xe2,0xfc,0xce,0xfa,0x7e,0x30,0x61,0x36,0x7f,0x1d,0x57,0xa4,0xe7,0x45,0x5a};
    Buffer vector;
    success(aes_gcm_encrypt(zero_key, sizeof(zero_key), nonce, sizeof(nonce), nullptr, 0, nullptr, 0, &vector.data, &vector.size));
    require(vector.size == sizeof(tag) && !std::memcmp(vector.data, tag, sizeof(tag)), "AES-GCM known vector failed");
    for (int parameter : {44, 65, 87}) {
        Buffer pk, sk, signature, empty, invalid;
        size_t pn, sn, sign;
        success(ml_dsa_get_sizes(parameter, &pn, &sn, &sign));
        success(ml_dsa_generate_keypair(parameter, &pk.data, &pk.size, &sk.data, &sk.size));
        require(pk.size == pn && sk.size == sn, "ML-DSA sizes mismatch");
        success(ml_dsa_sign(parameter, message, sizeof(message), sk.data, sk.size, &signature.data, &signature.size));
        require(signature.size == sign, "signature size mismatch");
        success(ml_dsa_verify(parameter, message, sizeof(message), signature.data, signature.size, pk.data, pk.size));
        success(ml_dsa_sign(parameter, nullptr, 0, sk.data, sk.size, &empty.data, &empty.size));
        success(ml_dsa_verify(parameter, nullptr, 0, empty.data, empty.size, pk.data, pk.size));
        require(ml_dsa_verify(parameter, message, sizeof(message), signature.data, signature.size, pk.data, pk.size - 1) == HCPABE_ERR_INVALID_KEY, "short public key accepted");
        signature.data[0] ^= 1;
        require(ml_dsa_verify(parameter, message, sizeof(message), signature.data, signature.size, pk.data, pk.size) == HCPABE_ERR_SIGNATURE_INVALID, "bad signature accepted");
        rejected(ml_dsa_sign(parameter, message, sizeof(message), sk.data, sk.size - 1, &invalid.data, &invalid.size), invalid);
    }
    for (int parameter : {512, 768, 1024}) {
        Buffer pk, sk, ct, ss, pt, invalid, invalid_ss, rejected_ss;
        size_t pn, sn, cn, ssn;
        success(ml_kem_get_sizes(parameter, &pn, &sn, &cn, &ssn));
        success(ml_kem_generate_keypair(parameter, &pk.data, &pk.size, &sk.data, &sk.size));
        success(ml_kem_encapsulate(parameter, pk.data, pk.size, &ct.data, &ct.size, &ss.data, &ss.size));
        require(pk.size == pn && sk.size == sn && ct.size == cn && ss.size == ssn, "ML-KEM sizes mismatch");
        success(ml_kem_decapsulate(parameter, sk.data, sk.size, ct.data, ct.size, &pt.data, &pt.size));
        require(pt.size == ss.size && !std::memcmp(pt.data, ss.data, ss.size), "KEM secret mismatch");
        rejected(ml_kem_encapsulate(parameter, pk.data, pk.size - 1, &invalid.data, &invalid.size, &invalid_ss.data, &invalid_ss.size), invalid);
        require(!invalid_ss.data && !invalid_ss.size, "KEM failed output not reset");
        rejected(ml_kem_decapsulate(parameter, sk.data, sk.size - 1, ct.data, ct.size, &invalid.data, &invalid.size), invalid);
        rejected(ml_kem_decapsulate(parameter, sk.data, sk.size, ct.data, ct.size - 1, &invalid.data, &invalid.size), invalid);
        ct.data[0] ^= 1;
        success(ml_kem_decapsulate(parameter, sk.data, sk.size, ct.data, ct.size, &rejected_ss.data, &rejected_ss.size));
        require(rejected_ss.size == ss.size && std::memcmp(rejected_ss.data, ss.data, ss.size), "implicit rejection failed");
    }
    Buffer invalid, other;
    rejected(aes_gcm_generate_key(129, &invalid.data, &invalid.size), invalid);
    rejected(ml_dsa_generate_keypair(45, &invalid.data, &invalid.size, &other.data, &other.size), invalid);
    rejected(ml_kem_generate_keypair(2014, &invalid.data, &invalid.size, &other.data, &other.size), invalid);
    rejected(ml_kem_generate_keypair(768, &invalid.data, &invalid.size, &invalid.data, &invalid.size), invalid);
    std::cout << "PASS AES known vector, primitive variants, length checks and implicit rejection\n";
}
void check_scheme(CPABEScheme scheme) {
    const std::string policy = "admin and it";
    for (int parameter : {44, 65, 87}) {
        Buffer pk, msk, verify, sign, user, denied;
        success(hybrid_cpabe_setupBuffer_with_ml_dsa(&pk.data, &pk.size, &msk.data, &msk.size,
            &verify.data, &verify.size, &sign.data, &sign.size, scheme, parameter));
        success(hybrid_cpabe_genkeyBuffer_with_scheme(msk.data, msk.size, "admin it", &user.data, &user.size, scheme));
        success(hybrid_cpabe_genkeyBuffer_with_scheme(msk.data, msk.size, "admin", &denied.data, &denied.size, scheme));
        for (int bits : {128, 192, 256}) {
            for (const std::string message : {std::string(), std::string("hello\0\xff", 7)}) {
                Buffer ct, pt, signed_ct, verified;
                success(hybrid_cpabe_encryptBuffer_with_params(pk.data, pk.size,
                    reinterpret_cast<const unsigned char *>(message.data()), message.size(), policy.c_str(),
                    &ct.data, &ct.size, scheme, bits));
                require(ct.data[0] == 3 && ct.data[2] == bits / 8 && ct.data[3] == 0, "wrong V3 metadata");
                success(hybrid_cpabe_decryptBuffer(user.data, user.size, ct.data, ct.size, &pt.data, &pt.size));
                same(pt, message);
                success(hybrid_cpabe_encryptBuffer_and_sign_with_params(pk.data, pk.size, sign.data, sign.size,
                    reinterpret_cast<const unsigned char *>(message.data()), message.size(), policy.c_str(),
                    &signed_ct.data, &signed_ct.size, scheme, bits, parameter));
                require(signed_ct.data[3] == parameter, "signature parameter missing");
                success(hybrid_cpabe_decryptBuffer_and_verify(user.data, user.size, verify.data, verify.size,
                    signed_ct.data, signed_ct.size, &verified.data, &verified.size));
                same(verified, message);
                Buffer fail;
                rejected(hybrid_cpabe_decryptBuffer_and_verify(denied.data, denied.size, verify.data, verify.size,
                    signed_ct.data, signed_ct.size, &fail.data, &fail.size), fail);
                rejected(hybrid_cpabe_decryptBuffer_and_verify(user.data, user.size, verify.data, verify.size,
                    ct.data, ct.size, &fail.data, &fail.size), fail);
                for (size_t position : {size_t(1), size_t(2), size_t(3), size_t(4), size_t(16), signed_ct.size - 1}) {
                    const auto old = signed_ct.data[position];
                    signed_ct.data[position] = position == 2 ? (old == 16 ? 24 : 16) : position == 3 ? (old == 44 ? 65 : 44) : old ^ 1;
                    rejected(hybrid_cpabe_decryptBuffer_and_verify(user.data, user.size, verify.data, verify.size,
                        signed_ct.data, signed_ct.size, &fail.data, &fail.size), fail);
                    signed_ct.data[position] = old;
                }
                for (size_t length : {size_t(0), size_t(3), size_t(23), size_t(24), signed_ct.size - 1})
                    rejected(hybrid_cpabe_decryptBuffer_and_verify(user.data, user.size, verify.data, verify.size,
                        signed_ct.data, length, &fail.data, &fail.size), fail);
            }
        }
        Buffer invalid;
        rejected(hybrid_cpabe_encryptBuffer_and_sign_with_params(pk.data, pk.size, sign.data, sign.size - 4,
            nullptr, 0, "admin", &invalid.data, &invalid.size, scheme, 256, parameter), invalid);
        rejected(hybrid_cpabe_encryptBuffer_with_params(pk.data, pk.size, nullptr, 0, "admin",
            &invalid.data, &invalid.size, scheme, 64), invalid);
        rejected(hybrid_cpabe_encryptBuffer_with_params(nullptr, 0, nullptr, 0, "admin",
            &invalid.data, &invalid.size, scheme, 256), invalid);
        rejected(hybrid_cpabe_encryptBuffer_with_params(pk.data, pk.size, nullptr, 0, "admin",
            &invalid.data, &invalid.size, static_cast<CPABEScheme>(99), 256), invalid);
        rejected(hybrid_cpabe_encryptBuffer_and_sign_with_params(pk.data, pk.size, sign.data, sign.size,
            nullptr, 0, "admin", &invalid.data, &invalid.size, scheme, 256, 45), invalid);
        if (parameter == 87) {
            Buffer legacy, recovered, legacy_signed, verified, defaults;
            success(hybrid_cpabe_encryptBuffer_with_scheme(pk.data, pk.size, nullptr, 0, policy.c_str(),
                &legacy.data, &legacy.size, scheme));
            require(legacy.data[0] == 2, "legacy writer format changed");
            success(hybrid_cpabe_decryptBuffer(user.data, user.size, legacy.data, legacy.size, &recovered.data, &recovered.size));
            same(recovered, "");
            success(hybrid_cpabe_encryptBuffer_and_sign_with_scheme(pk.data, pk.size, sign.data, sign.size,
                nullptr, 0, policy.c_str(), &legacy_signed.data, &legacy_signed.size, scheme));
            require(legacy_signed.data[0] == 2, "legacy signed writer changed");
            success(hybrid_cpabe_decryptBuffer_and_verify(user.data, user.size, verify.data, verify.size,
                legacy_signed.data, legacy_signed.size, &verified.data, &verified.size));
            same(verified, "");
            success(hybrid_cpabe_encryptBuffer_and_sign_with_params(pk.data, pk.size, sign.data, sign.size,
                nullptr, 0, policy.c_str(), &defaults.data, &defaults.size, scheme, 0, 0));
            require(defaults.data[2] == 32 && defaults.data[3] == 87, "wrong defaults");
        }
    }
    std::cout << "PASS scheme " << scheme << ": all AES/ML-DSA combinations, legacy, tamper and failures\n";
}
void check_files(CPABEScheme scheme) {
    const auto prefix = std::string("params-file-") + std::to_string(int(scheme));
    const std::string message("file\0payload\xff", 13);
    std::ofstream(prefix + "-plain", std::ios::binary).write(message.data(), message.size());
    for (int parameter : {44, 65, 87}) {
        success(hybrid_cpabe_setup_with_ml_dsa(prefix.c_str(), scheme, parameter));
        success(generateSecretKey_with_scheme((prefix + "_msk.key").c_str(), "admin it", (prefix + "-user").c_str(), scheme));
        for (int bits : {128, 192, 256}) {
            success(hybrid_cpabe_encrypt_with_params((prefix + "_pk.key").c_str(), (prefix + "-plain").c_str(),
                "admin and it", (prefix + "-ct").c_str(), scheme, bits));
            success(hybrid_cpabe_decrypt((prefix + "-user").c_str(), (prefix + "-ct").c_str(), (prefix + "-pt").c_str()));
            std::ifstream unsigned_file(prefix + "-pt", std::ios::binary);
            require(std::string(std::istreambuf_iterator<char>(unsigned_file), {}) == message, "file payload mismatch");
            success(hybrid_cpabe_encrypt_and_sign_with_params((prefix + "_pk.key").c_str(), (prefix + "_pqc_sk.key").c_str(),
                (prefix + "-plain").c_str(), "admin and it", (prefix + "-ct").c_str(), scheme, bits, parameter));
            success(hybrid_cpabe_decrypt_and_verify((prefix + "-user").c_str(), (prefix + "_pqc_pk.key").c_str(),
                (prefix + "-ct").c_str(), (prefix + "-pt").c_str()));
            std::ifstream file(prefix + "-pt", std::ios::binary);
            require(std::string(std::istreambuf_iterator<char>(file), {}) == message, "signed file payload mismatch");
        }
    }
    std::cout << "PASS parameterized files scheme " << scheme << '\n';
}
}
int main() {
    try {
        check_primitives();
        Buffer invalid_pk, invalid_msk, invalid_verify, invalid_sign;
        require(hybrid_cpabe_setupBuffer_with_ml_dsa(&invalid_pk.data, &invalid_pk.size,
            &invalid_msk.data, &invalid_msk.size, &invalid_verify.data, &invalid_verify.size,
            &invalid_sign.data, &invalid_sign.size, CPABE_SCHEME_AC17, 45) == HCPABE_ERR_INVALID_PARAM,
            "invalid setup parameter accepted");
        require(!invalid_pk.data && !invalid_pk.size && !invalid_msk.data && !invalid_msk.size &&
            !invalid_verify.data && !invalid_verify.size && !invalid_sign.data && !invalid_sign.size,
            "failed setup outputs not reset");
        require(hybrid_cpabe_setupBuffer_with_ml_dsa(&invalid_pk.data, &invalid_pk.size,
            &invalid_pk.data, &invalid_pk.size, &invalid_verify.data, &invalid_verify.size,
            &invalid_sign.data, &invalid_sign.size, CPABE_SCHEME_AC17, 87) == HCPABE_ERR_INVALID_PARAM,
            "aliased setup outputs accepted");
        const char *config = "params-test-config.json";
        std::ofstream(config) << R"({"dimensions":[{"name":"admin","attributes":["present","absent"]},{"name":"it","attributes":["present","absent"]}]})";
        environment("HCPABE_COVERCRYPT_CONFIG", config);
        environment("HCPABE_COVERCRYPT_MODE", "hybridized");
        require(hybrid_cpabe_covercrypt_ml_kem_parameter_set() == 768, "CoverCrypt provider changed");
        for (auto scheme : {CPABE_SCHEME_AC17, CPABE_SCHEME_TKN20, CPABE_SCHEME_COVERCRYPT}) {
            check_scheme(scheme);
            check_files(scheme);
        }
        std::cout << "PASS parameterized hybrid API\n";
        return 0;
    } catch (const std::exception &e) { std::cerr << e.what() << '\n'; return 1; }
}
