#include "hybrid_pq_cp_abe/hybrid-pq-cp-abe.h"
#include <covercrypt/covercrypt_ffi.h>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <vector>

namespace
{
using Bytes = std::vector<unsigned char>;
void require(bool ok, const char *message)
{
    if (!ok)
        throw std::runtime_error(message);
}
struct Buffer
{
    unsigned char *data = nullptr;
    size_t length = 0;
    Buffer() = default;
    Buffer(const Buffer &) = delete;
    Buffer &operator=(const Buffer &) = delete;
    ~Buffer()
    {
        freeBuffer(data);
    }
};
void environment(const char *name, const char *value)
{
#ifdef _WIN32
    require(_putenv_s(name, value) == 0, "environment setup failed");
#else
    require(setenv(name, value, 1) == 0, "environment setup failed");
#endif
}
bool equal(const Buffer &result, const Bytes &expected)
{
    return result.length == expected.size() &&
           (expected.empty() || std::memcmp(result.data, expected.data(), expected.size()) == 0);
}
struct CoverCryptBuffer
{
    cc_buffer value{nullptr, 0};
    CoverCryptBuffer() = default;
    CoverCryptBuffer(const CoverCryptBuffer &) = delete;
    CoverCryptBuffer &operator=(const CoverCryptBuffer &) = delete;
    ~CoverCryptBuffer()
    {
        cc_buffer_free(&value);
    }
};
bool equal(const CoverCryptBuffer &left, const CoverCryptBuffer &right)
{
    return left.value.len == right.value.len &&
           (left.value.len == 0 || std::memcmp(left.value.data, right.value.data, left.value.len) == 0);
}
void check_ephemeral_genkey()
{
    const char *config = R"({"dimensions":[{"name":"DPT","attributes":["FIN","HR"]}]})";
    for (int mode : {CC_CLASSIC, CC_POST_QUANTUM, CC_HYBRIDIZED})
    {
        CoverCryptBuffer msk, mpk, updated, persisted_user, ephemeral_user, denied_user;
        require(cc_setup(config, mode, &msk.value, &mpk.value) == CC_OK, "ephemeral setup failed");
        const Bytes original(msk.value.data, msk.value.data + msk.value.len);
        require(cc_genkey(msk.value.data, msk.value.len, "DPT::FIN", &updated.value,
                          &persisted_user.value) == CC_OK, "persisted genkey failed");
        require(cc_genkey_ephemeral(msk.value.data, msk.value.len, "DPT::FIN",
                                    &ephemeral_user.value) == CC_OK, "ephemeral genkey failed");
        require(cc_genkey_ephemeral(msk.value.data, msk.value.len, "DPT::HR",
                                    &denied_user.value) == CC_OK, "denied-user genkey failed");
        require(msk.value.len == original.size() &&
                    std::memcmp(msk.value.data, original.data(), original.size()) == 0,
                "ephemeral genkey changed its input master key");
        CoverCryptBuffer secret, encapsulation;
        require(cc_encaps(mpk.value.data, mpk.value.len, "DPT::FIN", &secret.value,
                          &encapsulation.value) == CC_OK, "ephemeral encaps failed");
        for (const auto *user : {&persisted_user, &ephemeral_user})
        {
            CoverCryptBuffer recovered;
            require(cc_decaps(user->value.data, user->value.len, encapsulation.value.data,
                              encapsulation.value.len, &recovered.value) == CC_OK && equal(secret, recovered),
                    "persisted/ephemeral user permissions differ");
        }
        CoverCryptBuffer denied;
        require(cc_decaps(denied_user.value.data, denied_user.value.len, encapsulation.value.data,
                          encapsulation.value.len, &denied.value) == CC_ACCESS_DENIED && !denied.value.data,
                "ephemeral genkey widened access rights");
        require(cc_genkey_ephemeral(msk.value.data, msk.value.len, "DPT::FIN", nullptr) == CC_INVALID_INPUT,
                "ephemeral genkey accepted null output");
        require(cc_genkey_ephemeral(msk.value.data, msk.value.len, "DPT::FIN",
                                    &ephemeral_user.value) == CC_INVALID_INPUT,
                "ephemeral genkey overwrote a nonempty output");
        require(cc_genkey_ephemeral(nullptr, 0, "DPT::FIN", &denied.value) == CC_INVALID_INPUT,
                "ephemeral genkey accepted null master key");
    }
    std::cout << "PASS: ephemeral genkey preserves permissions and ownership in all modes\n";
}
void check_attribute_growth()
{
    const char *initial_config =
        R"({"dimensions":[{"name":"DPT","attributes":["FIN","HR"]},{"name":"SEC","attributes":["LOW","TOP"],"hierarchical":true}]})";

    CoverCryptBuffer initial_msk, initial_mpk;
    require(cc_setup(initial_config, CC_HYBRIDIZED, &initial_msk.value, &initial_mpk.value) == CC_OK,
            "attribute-growth setup failed");

    CoverCryptBuffer authority_after_old_user, old_user;
    require(cc_genkey(initial_msk.value.data, initial_msk.value.len, "DPT::FIN && SEC::TOP",
                      &authority_after_old_user.value, &old_user.value) == CC_OK,
            "old-attribute user key generation failed");

    CoverCryptBuffer old_secret, old_encapsulation, old_recovered;
    require(cc_encaps(initial_mpk.value.data, initial_mpk.value.len, "DPT::FIN && SEC::LOW",
                      &old_secret.value, &old_encapsulation.value) == CC_OK,
            "old-attribute encryption failed");
    require(cc_decaps(old_user.value.data, old_user.value.len,
                      old_encapsulation.value.data, old_encapsulation.value.len,
                      &old_recovered.value) == CC_OK &&
                equal(old_secret, old_recovered),
            "old-attribute ciphertext did not decrypt before policy growth");

    CoverCryptBuffer grown_msk, grown_mpk;
    require(cc_add_attribute(authority_after_old_user.value.data, authority_after_old_user.value.len,
                             "DPT", "Sales", CC_HYBRIDIZED, nullptr,
                             &grown_msk.value, &grown_mpk.value) == CC_OK,
            "adding DPT::Sales to existing authority failed");

    CoverCryptBuffer authority_after_new_user, sales_user;
    require(cc_genkey(grown_msk.value.data, grown_msk.value.len, "DPT::Sales && SEC::TOP",
                      &authority_after_new_user.value, &sales_user.value) == CC_OK,
            "updated master key could not mint a user key for DPT::Sales");

    CoverCryptBuffer sales_secret, sales_encapsulation, sales_recovered;
    require(cc_encaps(grown_mpk.value.data, grown_mpk.value.len, "DPT::Sales && SEC::LOW",
                      &sales_secret.value, &sales_encapsulation.value) == CC_OK,
            "new-attribute encryption failed");
    require(cc_decaps(sales_user.value.data, sales_user.value.len,
                      sales_encapsulation.value.data, sales_encapsulation.value.len,
                      &sales_recovered.value) == CC_OK &&
                equal(sales_secret, sales_recovered),
            "new DPT::Sales user could not decrypt new-attribute ciphertext");

    CoverCryptBuffer old_recovered_after_growth;
    require(cc_decaps(old_user.value.data, old_user.value.len,
                      old_encapsulation.value.data, old_encapsulation.value.len,
                      &old_recovered_after_growth.value) == CC_OK &&
                equal(old_secret, old_recovered_after_growth),
            "policy growth invalidated an existing ciphertext/user key");

    CoverCryptBuffer current_old_secret, current_old_encapsulation, current_old_recovered;
    require(cc_encaps(grown_mpk.value.data, grown_mpk.value.len, "DPT::FIN && SEC::LOW",
                      &current_old_secret.value, &current_old_encapsulation.value) == CC_OK,
            "updated public key could not encrypt an existing attribute");
    require(cc_decaps(old_user.value.data, old_user.value.len,
                      current_old_encapsulation.value.data, current_old_encapsulation.value.len,
                      &current_old_recovered.value) == CC_OK &&
                equal(current_old_secret, current_old_recovered),
            "existing user key could not decrypt existing rights after policy growth");

    std::cout << "PASS: CoverCrypt attribute growth preserves old access and mints new user keys\n";
}
void check_mode(const char *mode)
{
    environment("HCPABE_COVERCRYPT_MODE", mode);
    Buffer pk, msk, sign_pk, sign_sk, alice, bob;
    require(hybrid_cpabe_setupBuffer_with_pqc_scheme(&pk.data, &pk.length, &msk.data, &msk.length, &sign_pk.data,
                                                     &sign_pk.length, &sign_sk.data, &sign_sk.length,
                                                     CPABE_SCHEME_COVERCRYPT) == HCPABE_SUCCESS,
            "v5.2 setup + PQC API failed");
    require(hybrid_cpabe_genkeyBuffer_with_scheme(msk.data, msk.length, "DPT::FIN && SEC::TOP", &alice.data,
                                                  &alice.length, CPABE_SCHEME_COVERCRYPT) == HCPABE_SUCCESS,
            "v5.2 genkey API failed");
    require(hybrid_cpabe_genkeyBuffer_with_scheme(msk.data, msk.length, "DPT::HR && SEC::TOP", &bob.data, &bob.length,
                                                  CPABE_SCHEME_COVERCRYPT) == HCPABE_SUCCESS,
            "second buffer genkey failed");
    Buffer partial;
    require(hybrid_cpabe_genkeyBuffer_with_scheme(msk.data, msk.length, "DPT::FIN", &partial.data,
                                                  &partial.length, CPABE_SCHEME_COVERCRYPT) == HCPABE_SUCCESS,
            "partial-attribute key generation failed");
    for (const Bytes &message : {Bytes{}, Bytes{0, 1, 2, 0, 255}})
    {
        Buffer ct, recovered, denied;
        require(hybrid_cpabe_encryptBuffer_with_scheme(pk.data, pk.length, message.data(), message.size(),
                                                       "DPT::FIN && SEC::LOW", &ct.data, &ct.length,
                                                       CPABE_SCHEME_COVERCRYPT) == HCPABE_SUCCESS,
                "v5.2 encrypt API failed");
        require(hybrid_cpabe_decryptBuffer(alice.data, alice.length, ct.data, ct.length, &recovered.data,
                                           &recovered.length) == HCPABE_SUCCESS &&
                    equal(recovered, message),
                "auto-detect decrypt failed");
        require(hybrid_cpabe_decryptBuffer(bob.data, bob.length, ct.data, ct.length, &denied.data, &denied.length) ==
                        HCPABE_ERR_POLICY_MISMATCH &&
                    !denied.data,
                "unauthorized key accepted");
        require(hybrid_cpabe_decryptBuffer(partial.data, partial.length, ct.data, ct.length,
                                           &denied.data, &denied.length) == HCPABE_ERR_POLICY_MISMATCH && !denied.data,
                "omitting SEC granted a wildcard user key");
        ct.data[ct.length - 1] ^= 1;
        require(hybrid_cpabe_decryptBuffer(alice.data, alice.length, ct.data, ct.length, &denied.data,
                                           &denied.length) != HCPABE_SUCCESS &&
                    !denied.data,
                "tampered ciphertext accepted");
        for (size_t length : {size_t(1), size_t(2), size_t(10), size_t(22), size_t(23), size_t(38)})
            require(hybrid_cpabe_decryptBuffer(alice.data, alice.length, ct.data, length, &denied.data,
                                               &denied.length) != HCPABE_SUCCESS &&
                        !denied.data,
                    "truncated ciphertext accepted");
        Buffer signed_ct, verified;
        require(hybrid_cpabe_encryptBuffer_and_sign_with_scheme(pk.data, pk.length, sign_sk.data, sign_sk.length,
                                                                message.data(), message.size(), "DPT::FIN && SEC::LOW",
                                                                &signed_ct.data, &signed_ct.length,
                                                                CPABE_SCHEME_COVERCRYPT) == HCPABE_SUCCESS,
                "v5.2 sign API failed");
        require(hybrid_cpabe_decryptBuffer_and_verify(alice.data, alice.length, sign_pk.data, sign_pk.length,
                                                      signed_ct.data, signed_ct.length, &verified.data,
                                                      &verified.length) == HCPABE_SUCCESS &&
                    equal(verified, message),
                "v5.2 verify API failed");
        require(hybrid_cpabe_decryptBuffer_and_verify(partial.data, partial.length, sign_pk.data,
                                                      sign_pk.length, signed_ct.data, signed_ct.length,
                                                      &denied.data, &denied.length) == HCPABE_ERR_POLICY_MISMATCH &&
                    !denied.data,
                "signed ciphertext accepted a key missing SEC");
        require(hybrid_cpabe_decryptBuffer_and_verify(alice.data, alice.length, sign_pk.data, 1, signed_ct.data,
                                                      signed_ct.length, &denied.data,
                                                      &denied.length) != HCPABE_SUCCESS &&
                    !denied.data,
                "invalid verification key accepted");
        Buffer other_pk, other_msk, other_sign_pk, other_sign_sk;
        require(hybrid_cpabe_setupBuffer_with_pqc_scheme(&other_pk.data, &other_pk.length, &other_msk.data,
                                                         &other_msk.length, &other_sign_pk.data, &other_sign_pk.length,
                                                         &other_sign_sk.data, &other_sign_sk.length,
                                                         CPABE_SCHEME_COVERCRYPT) == HCPABE_SUCCESS,
                "wrong signer setup failed");
        require(hybrid_cpabe_decryptBuffer_and_verify(alice.data, alice.length, other_sign_pk.data,
                                                      other_sign_pk.length, signed_ct.data, signed_ct.length,
                                                      &denied.data, &denied.length) == HCPABE_ERR_SIGNATURE_INVALID &&
                    !denied.data,
                "wrong signer accepted");
        signed_ct.data[2] ^= 1;
        require(hybrid_cpabe_decryptBuffer(alice.data, alice.length, signed_ct.data, signed_ct.length, &denied.data,
                                           &denied.length) != HCPABE_SUCCESS &&
                    !denied.data,
                "tampered signed ciphertext accepted");
    }
    Buffer legacy_user, legacy_ct, legacy_pt;
    require(hybrid_cpabe_genkeyBuffer_with_scheme(msk.data, msk.length, "admin it", &legacy_user.data,
                                                  &legacy_user.length, CPABE_SCHEME_COVERCRYPT) == HCPABE_SUCCESS,
            "legacy attribute list rejected");
    const unsigned char message[] = "unchanged application API";
    require(hybrid_cpabe_encryptBuffer_with_scheme(pk.data, pk.length, message, sizeof(message), "\"admin\" AND \"it\"",
                                                   &legacy_ct.data, &legacy_ct.length,
                                                   CPABE_SCHEME_COVERCRYPT) == HCPABE_SUCCESS,
            "legacy AND policy rejected");
    require(hybrid_cpabe_decryptBuffer(legacy_user.data, legacy_user.length, legacy_ct.data, legacy_ct.length,
                                       &legacy_pt.data, &legacy_pt.length) == HCPABE_SUCCESS &&
                legacy_pt.length == sizeof(message) && std::memcmp(legacy_pt.data, message, sizeof(message)) == 0,
            "legacy-style application round trip failed");
    std::cout << "PASS: " << mode << " through v5.2 setup/genkey/encrypt/decrypt/sign/verify APIs\n";
}
void check_files(const std::string &prefix)
{
    require(hybrid_cpabe_setup_with_pqc_scheme(prefix.c_str(), CPABE_SCHEME_COVERCRYPT) == HCPABE_SUCCESS,
            "file setup failed");
    std::string master = prefix + "_msk.key", user = prefix + "_user.key", pk = prefix + "_pk.key";
    std::string plain = prefix + "_plain", cipher = prefix + "_cipher", recovered = prefix + "_recovered";
    std::string sign = prefix + "_pqc_sk.key", verify = prefix + "_pqc_pk.key";
    std::ofstream(plain, std::ios::binary) << "legacy file API";
    require(generateSecretKey_with_scheme(master.c_str(), "admin it", user.c_str(), CPABE_SCHEME_COVERCRYPT) ==
                HCPABE_SUCCESS,
            "v5.2 file genkey failed");
    require(hybrid_cpabe_encrypt_with_scheme(pk.c_str(), plain.c_str(), "admin AND it", cipher.c_str(),
                                             CPABE_SCHEME_COVERCRYPT) == HCPABE_SUCCESS,
            "v5.2 file encrypt failed");
    require(hybrid_cpabe_decrypt(user.c_str(), cipher.c_str(), recovered.c_str()) == HCPABE_SUCCESS,
            "v5.2 file decrypt failed");
    require(hybrid_cpabe_encrypt_and_sign_with_scheme(pk.c_str(), sign.c_str(), plain.c_str(), "admin AND it",
                                                      cipher.c_str(), CPABE_SCHEME_COVERCRYPT) == HCPABE_SUCCESS,
            "v5.2 file sign failed");
    require(hybrid_cpabe_decrypt_and_verify(user.c_str(), verify.c_str(), cipher.c_str(), recovered.c_str()) ==
                HCPABE_SUCCESS,
            "v5.2 file verify failed");
    std::ifstream input(recovered, std::ios::binary);
    std::string output((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
    require(output == "legacy file API", "file payload changed");
    std::cout << "PASS: v5.2 file APIs\n";
}
} // namespace
int main()
{
    try
    {
        const char *config =
            R"({"dimensions":[{"name":"admin","attributes":["present","absent"]},{"name":"it","attributes":["present","absent"]},{"name":"hr","attributes":["present","absent"]},{"name":"DPT","attributes":["FIN","HR"]},{"name":"SEC","attributes":["LOW","TOP"],"hierarchical":true}]})";
#ifdef _WIN32
        const std::string prefix = "build/artifacts/windows/covercrypt-api-test";
#elif defined(__APPLE__)
        const std::string prefix = "build/artifacts/macos/covercrypt-api-test";
#else
        const std::string prefix = "build/artifacts/linux/covercrypt-api-test";
#endif
        std::string configuration = prefix + ".json";
        std::ofstream(configuration) << config;
        environment("HCPABE_COVERCRYPT_CONFIG", configuration.c_str());
        for (const char *mode : {"classic", "post_quantum", "hybridized"})
            check_mode(mode);
        check_attribute_growth();
        check_ephemeral_genkey();
        check_files(prefix);
        cc_buffer first{nullptr, 0}, second{nullptr, 0};
        require(cc_setup(nullptr, CC_HYBRIDIZED, &first, &second) == CC_INVALID_INPUT, "null input accepted");
        require(cc_setup(config, 99, &first, &second) == CC_INVALID_INPUT, "invalid mode accepted");
        require(cc_setup(config, CC_HYBRIDIZED, &first, &first) == CC_INVALID_INPUT, "aliased outputs accepted");
        cc_buffer_free(&first);
        cc_buffer_free(&first);
        std::cout << "PASS: C ABI validation and buffer cleanup\n";
        return 0;
    }
    catch (const std::exception &error)
    {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
