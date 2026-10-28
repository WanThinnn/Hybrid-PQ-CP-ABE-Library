#include <cryptopp/dll.h>
#include <cstring>
#include <cstdio>
#include <iostream>

int main() {
    try {
        const CryptoPP::byte key[16] = {};
        const CryptoPP::byte input[16] = {};
        const CryptoPP::byte expected[16] = {
            0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b,
            0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34, 0x2b, 0x2e
        };
        CryptoPP::byte output[16];
        CryptoPP::AES::Encryption aes(key, sizeof(key));
        aes.ProcessBlock(input, output);
        if (std::memcmp(output, expected, sizeof(output)) != 0) return 1;
        CryptoPP::SHA256 sha;
        CryptoPP::byte digest[CryptoPP::SHA256::DIGESTSIZE];
        sha.CalculateDigest(digest, reinterpret_cast<const CryptoPP::byte*>("abc"), 3);
        std::string hex;
        CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(hex));
        encoder.Put(digest, sizeof(digest));
        encoder.MessageEnd();
        if (hex != "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD") return 2;
        CryptoPP::AutoSeededRandomPool rng;
        rng.GenerateBlock(digest, sizeof(digest));
        if (CryptoPP::FIPS_140_2_ComplianceEnabled()) return 3;
        if (CryptoPP::GetPowerUpSelfTestStatus() != CryptoPP::POWER_UP_SELF_TEST_PASSED) return 4;
        std::puts("PASS: Crypto++ DLL AES/SHA256/RNG and power-up self-tests");
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 5;
    }
}
