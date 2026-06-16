/**
 * @file main.cpp
 * @brief CLI wrapper cho thư viện Hybrid CP-ABE (Unified with PQC)
 * 
 * File này cung cấp giao diện dòng lệnh để sử dụng các chức năng
 * của thư viện Hybrid CP-ABE. Hỗ trợ thêm cờ --pqc để sử dụng chữ ký lượng tử.
 */

#include <iostream>
#include <string>
#include <cstring>
#include <vector>
#include <algorithm>
#include <cryptopp/base64.h>
#include <cryptopp/filters.h>

#include "hybrid_pq_cp_abe/hybrid-pq-cp-abe.h"

void printUsage(const char* programName)
{
    std::cout << "Hybrid PQ-CP-ABE Library v" << getVersion() << std::endl;
    std::cout << "Usage: " << programName << " [command] [--pqc] [options]" << std::endl;
    std::cout << std::endl;
    std::cout << "Commands:" << std::endl;
    std::cout << "  setup   <path_or_prefix>                             - Generate Master Key and Public Key" << std::endl;
    std::cout << "  genkey  <master_key> <attrs> <out_file>              - Generate private key from attributes" << std::endl;
    std::cout << "  encrypt <pub_key> [pqc_priv_key] <file> <policy> <out> - Encrypt (and Sign) file" << std::endl;
    std::cout << "  decrypt <priv_key> [pqc_pub_key] <file> <out>         - Decrypt (and Verify) file" << std::endl;
    std::cout << "  encrypt_buffer <pub_key> [pqc_priv_key] <text> <policy> <out>  - Encrypt (and Sign) text string to file" << std::endl;
    std::cout << "  decrypt_buffer <priv_key> [pqc_pub_key] <file>                - Decrypt (and Verify) file to stdout" << std::endl;
    std::cout << std::endl;
    std::cout << "Examples:" << std::endl;
    std::cout << "  " << programName << " setup ./keys/mykey" << std::endl;
    std::cout << "  " << programName << " setup --pqc ./keys/mykey" << std::endl;
    std::cout << "  " << programName << " genkey ./keys/cpabe_msk.key \"admin it\" ./keys/user.key" << std::endl;
    std::cout << "  " << programName << " encrypt ./keys/cpabe_pk.key data.txt \"\\\"admin\\\" and \\\"it\\\"\" data.enc" << std::endl;
    std::cout << "  " << programName << " encrypt --pqc ./keys/cpabe_pk.key ./keys/pqc_sk.key data.txt \"\\\"admin\\\"\" data.enc" << std::endl;
}

#include <fstream>
#include <sstream>

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        printUsage(argv[0]);
        return 1;
    }
    
    std::vector<std::string> args;
    bool use_pqc = false;
    for (int i = 0; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--pqc") {
            use_pqc = true;
        } else {
            args.push_back(arg);
        }
    }

    if (args.size() < 2)
    {
        printUsage(args[0].c_str());
        return 1;
    }
    
    // Check if any argument is accidentally a reserved command (except args[1])
    std::vector<std::string> reserved_commands = {"setup", "genkey", "encrypt", "decrypt", "encrypt_buffer", "decrypt_buffer"};
    for (size_t i = 2; i < args.size(); ++i) {
        if (std::find(reserved_commands.begin(), reserved_commands.end(), args[i]) != reserved_commands.end()) {
            std::cerr << "Error: You used a reserved command name '" << args[i] << "' as an argument." << std::endl;
            std::cerr << "Execution stopped to prevent unintended file generation. Please check your command syntax." << std::endl;
            return 1;
        }
    }
    
    std::string mode = args[1];
    
    // Handle help command
    if (mode == "-h" || mode == "--help" || mode == "help")
    {
        printUsage(args[0].c_str());
        return 0;
    }
    
    // Handle version command
    if (mode == "-v" || mode == "--version" || mode == "version")
    {
        std::cout << "Hybrid PQ-CP-ABE Library v" << getVersion() << std::endl;
        return 0;
    }
    
    int result = HCPABE_SUCCESS;
    
    try
    {
        if (mode == "setup")
        {
            if (args.size() != 3)
            {
                std::cerr << "Usage: " << args[0] << " setup [--pqc] <path_or_prefix>" << std::endl;
                return 1;
            }
            if (use_pqc) {
                result = hybrid_cpabe_setup_with_pqc(args[2].c_str());
            } else {
                result = setup(args[2].c_str());
            }
        }
        else if (mode == "genkey")
        {
            if (args.size() != 5)
            {
                std::cerr << "Usage: " << args[0] << " genkey <master_key_file> <attributes> <private_key_file>" << std::endl;
                return 1;
            }
            result = generateSecretKey(args[2].c_str(), args[3].c_str(), args[4].c_str());
        }
        else if (mode == "encrypt")
        {
            if (use_pqc) {
                if (args.size() != 7) {
                    std::cerr << "Usage: " << args[0] << " encrypt --pqc <public_key_file> <pqc_private_key_file> <plaintext_file> <policy> <ciphertext_file>" << std::endl;
                    return 1;
                }
                result = hybrid_cpabe_encrypt_and_sign(args[2].c_str(), args[3].c_str(), args[4].c_str(), args[5].c_str(), args[6].c_str());
            } else {
                if (args.size() != 6) {
                    std::cerr << "Usage: " << args[0] << " encrypt <public_key_file> <plaintext_file> <policy> <ciphertext_file>" << std::endl;
                    return 1;
                }
                result = hybrid_cpabe_encrypt(args[2].c_str(), args[3].c_str(), args[4].c_str(), args[5].c_str());
            }
        }
        else if (mode == "decrypt")
        {
            if (use_pqc) {
                if (args.size() != 6) {
                    std::cerr << "Usage: " << args[0] << " decrypt --pqc <private_key_file> <pqc_public_key_file> <ciphertext_file> <recovertext_file>" << std::endl;
                    return 1;
                }
                result = hybrid_cpabe_decrypt_and_verify(args[2].c_str(), args[3].c_str(), args[4].c_str(), args[5].c_str());
            } else {
                if (args.size() != 5) {
                    std::cerr << "Usage: " << args[0] << " decrypt <private_key_file> <ciphertext_file> <recovertext_file>" << std::endl;
                    return 1;
                }
                result = hybrid_cpabe_decrypt(args[2].c_str(), args[3].c_str(), args[4].c_str());
            }
        }
        else if (mode == "encrypt_buffer")
        {
            if (use_pqc) {
                if (args.size() != 7) {
                    std::cerr << "Usage: " << args[0] << " encrypt_buffer --pqc <public_key_file> <pqc_private_key_file> <text_string> <policy> <ciphertext_file>" << std::endl;
                    return 1;
                }
                // Read PK
                std::ifstream pkFile(args[2], std::ios::binary);
                if (!pkFile) return 1;
                std::string pkStr((std::istreambuf_iterator<char>(pkFile)), std::istreambuf_iterator<char>());
                pkFile.close();
                std::string decodedPkStr;
                CryptoPP::StringSource(pkStr, true, new CryptoPP::Base64Decoder(new CryptoPP::StringSink(decodedPkStr)));
                
                // Read PQC SK
                std::ifstream mskFile(args[3], std::ios::binary);
                if (!mskFile) return 1;
                std::string mskStr((std::istreambuf_iterator<char>(mskFile)), std::istreambuf_iterator<char>());
                mskFile.close();
                std::string decodedMskStr;
                CryptoPP::StringSource(mskStr, true, new CryptoPP::Base64Decoder(new CryptoPP::StringSink(decodedMskStr)));
                
                std::string ptStr = args[4];
                unsigned char* ct = nullptr;
                size_t ctLen = 0;
                
                result = hybrid_cpabe_encryptBuffer_and_sign(
                                                    (const unsigned char*)decodedPkStr.data(), decodedPkStr.size(), 
                                                    (const unsigned char*)decodedMskStr.data(), decodedMskStr.size(), 
                                                    (const unsigned char*)ptStr.data(), ptStr.size(), 
                                                    args[5].c_str(), &ct, &ctLen);
                if (result == HCPABE_SUCCESS) {
                    std::ofstream outFile(args[6], std::ios::binary);
                    outFile.write((char*)ct, ctLen);
                    outFile.close();
                    freeBuffer(ct);
                }
            } else {
                if (args.size() != 6) {
                    std::cerr << "Usage: " << args[0] << " encrypt_buffer <public_key_file> <text_string> <policy> <ciphertext_file>" << std::endl;
                    return 1;
                }
                // Read PK
                std::ifstream pkFile(args[2], std::ios::binary);
                if (!pkFile) { std::cerr << "Cannot open public key file." << std::endl; return 1; }
                std::string pkStr((std::istreambuf_iterator<char>(pkFile)), std::istreambuf_iterator<char>());
                pkFile.close();
                
                std::string decodedPkStr;
                CryptoPP::StringSource(pkStr, true, new CryptoPP::Base64Decoder(new CryptoPP::StringSink(decodedPkStr)));
                
                std::string ptStr = args[3];
                unsigned char* ct = nullptr;
                size_t ctLen = 0;
                
                result = hybrid_cpabe_encryptBuffer((const unsigned char*)decodedPkStr.data(), decodedPkStr.size(), 
                                                    (const unsigned char*)ptStr.data(), ptStr.size(), 
                                                    args[4].c_str(), &ct, &ctLen);
                if (result == HCPABE_SUCCESS) {
                    std::ofstream outFile(args[5], std::ios::binary);
                    outFile.write((char*)ct, ctLen);
                    outFile.close();
                    freeBuffer(ct);
                }
            }
        }
        else if (mode == "decrypt_buffer")
        {
            if (use_pqc) {
                if (args.size() != 5) {
                    std::cerr << "Usage: " << args[0] << " decrypt_buffer --pqc <private_key_file> <pqc_public_key_file> <ciphertext_file>" << std::endl;
                    return 1;
                }
                // Read SK
                std::ifstream skFile(args[2], std::ios::binary);
                if (!skFile) return 1;
                std::string skStr((std::istreambuf_iterator<char>(skFile)), std::istreambuf_iterator<char>());
                skFile.close();
                std::string decodedSkStr;
                CryptoPP::StringSource(skStr, true, new CryptoPP::Base64Decoder(new CryptoPP::StringSink(decodedSkStr)));
                
                // Read PQC PK
                std::ifstream pkFile(args[3], std::ios::binary);
                if (!pkFile) return 1;
                std::string pkStr((std::istreambuf_iterator<char>(pkFile)), std::istreambuf_iterator<char>());
                pkFile.close();
                std::string decodedPkStr;
                CryptoPP::StringSource(pkStr, true, new CryptoPP::Base64Decoder(new CryptoPP::StringSink(decodedPkStr)));
                
                // Read CT
                std::ifstream ctFile(args[4], std::ios::binary);
                if (!ctFile) return 1;
                std::string ctStr((std::istreambuf_iterator<char>(ctFile)), std::istreambuf_iterator<char>());
                ctFile.close();
                
                unsigned char* pt = nullptr;
                size_t ptLen = 0;
                
                result = hybrid_cpabe_decryptBuffer_and_verify(
                                                    (const unsigned char*)decodedSkStr.data(), decodedSkStr.size(), 
                                                    (const unsigned char*)decodedPkStr.data(), decodedPkStr.size(), 
                                                    (const unsigned char*)ctStr.data(), ctStr.size(), 
                                                    &pt, &ptLen);
                if (result == HCPABE_SUCCESS) {
                    std::string ptOut((char*)pt, ptLen);
                    std::cout << "Decrypted Buffer: " << ptOut << std::endl;
                    freeBuffer(pt);
                }
            } else {
                if (args.size() != 4) {
                    std::cerr << "Usage: " << args[0] << " decrypt_buffer <private_key_file> <ciphertext_file>" << std::endl;
                    return 1;
                }
                // Read SK
                std::ifstream skFile(args[2], std::ios::binary);
                if (!skFile) { std::cerr << "Cannot open private key file." << std::endl; return 1; }
                std::string skStr((std::istreambuf_iterator<char>(skFile)), std::istreambuf_iterator<char>());
                skFile.close();
                
                std::string decodedSkStr;
                CryptoPP::StringSource(skStr, true, new CryptoPP::Base64Decoder(new CryptoPP::StringSink(decodedSkStr)));
                
                // Read CT
                std::ifstream ctFile(args[3], std::ios::binary);
                if (!ctFile) { std::cerr << "Cannot open ciphertext file." << std::endl; return 1; }
                std::string ctStr((std::istreambuf_iterator<char>(ctFile)), std::istreambuf_iterator<char>());
                ctFile.close();
                
                unsigned char* pt = nullptr;
                size_t ptLen = 0;
                
                result = hybrid_cpabe_decryptBuffer((const unsigned char*)decodedSkStr.data(), decodedSkStr.size(), 
                                                    (const unsigned char*)ctStr.data(), ctStr.size(), 
                                                    &pt, &ptLen);
                if (result == HCPABE_SUCCESS) {
                    std::string ptOut((char*)pt, ptLen);
                    std::cout << "Decrypted Buffer: " << ptOut << std::endl;
                    freeBuffer(pt);
                }
            }
        }
        else
        {
            std::cerr << "Error: Invalid command '" << mode << "'" << std::endl;
            std::cerr << "Use '" << args[0] << " --help' for usage information." << std::endl;
            return 1;
        }
        
        // Print error message if operation failed
        if (result != HCPABE_SUCCESS)
        {
            std::cerr << "Operation failed: " << getErrorMessage(result) << " (code: " << result << ")" << std::endl;
        }
    }
    catch (const std::exception &ex)
    {
        std::cerr << "Exception: " << ex.what() << std::endl;
        return 1;
    }
    
    return (result == HCPABE_SUCCESS) ? 0 : 1;
}
