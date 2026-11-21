/**
 * @file main.cpp
 * @brief Command-line interface for scheme selection, encryption, and ML-DSA signatures.
 */

#include <iostream>
#include <string>
#include <cstring>
#include <vector>
#include <algorithm>
#include <cryptopp/base64.h>
#include <cryptopp/filters.h>
#include <fstream>
#include <map>
#include <sstream>

#include "core/abe-internal.h"

namespace
{
constexpr const char *cliName = "pq-cp-abe";

struct CommandHelp
{
    const char *name;
    const char *syntax;
    const char *description;
};

constexpr CommandHelp commands[] = {
    {"setup", "[--scheme NAME] [--with-signing-keys [--ml-dsa SET]] <path-or-prefix>",
     "Create an authority public key and master secret key."},
    {"genkey", "[--scheme NAME] <master-key> <attributes> <user-key>",
     "Issue a user key for the given attributes."},
    {"encrypt", "[--scheme NAME] [--aes-bits BITS] [--sign [--ml-dsa SET]]\n"
                "    <public-key> [signing-key] <input> <policy> <output>",
     "Encrypt a file. With positional arguments and --sign, pass the signing key after the public key."},
    {"decrypt", "[--verify] <user-key> [verification-key] <input> <output>",
     "Decrypt a file. With positional arguments and --verify, pass the verification key after the user key."},
    {"setup_buffer", "[--scheme NAME] [--with-signing-keys [--ml-dsa SET]]",
     "Create an authority and print its keys as Base64."},
    {"genkey_buffer", "[--scheme NAME] <master-key> <attributes>",
     "Issue a user key and print it as Base64."},
    {"encrypt_buffer", "[--scheme NAME] [--aes-bits BITS] [--sign [--ml-dsa SET]]\n"
                       "    <public-key> [signing-key] <text> <policy> <output>",
     "Encrypt text to a file. With --sign, pass the signing key after the public key."},
    {"decrypt_buffer", "[--verify] <user-key> [verification-key] <input>",
     "Decrypt a file and print the plaintext. With --verify, pass the verification key after the user key."},
    {"add_dimension", "--scheme covercrypt <master-key> <dimension-json> <new-prefix>",
     "Add a dimension without replacing the authority. Use a new output prefix."},
    {"add_attribute", "--scheme covercrypt <master-key> <dimension> <attribute>\n"
                      "    <new-prefix> [after-attribute]",
     "Add an attribute without replacing the authority. Use a new output prefix."},
    {"version", "", "Show the library version."},
    {"help", "[command]", "Show general help or help for one command."},
};

struct NamedCommand
{
    std::string name;
    const char *syntax;
    std::vector<std::string> fields;
    std::string signatureKeyField;
};

const NamedCommand namedCommands[] = {
    {"setup", "[--scheme NAME] [--with-signing-keys [--ml-dsa SET]] --file PATH-OR-PREFIX",
     {"--file"}, ""},
    {"genkey", "[--scheme NAME] --master-key FILE --attributes ATTRIBUTES --user-key FILE",
     {"--master-key", "--attributes", "--user-key"}, ""},
    {"encrypt", "--public-key FILE --file FILE --policy POLICY --ciphertext FILE\n"
                "    [--scheme NAME] [--aes-bits BITS] [--sign --signing-key FILE [--ml-dsa SET]]",
     {"--public-key", "--signing-key", "--file", "--policy", "--ciphertext"}, "--signing-key"},
    {"decrypt", "--user-key FILE --ciphertext FILE --output FILE\n"
                "    [--verify --verification-key FILE]",
     {"--user-key", "--verification-key", "--ciphertext", "--output"}, "--verification-key"},
};

const NamedCommand *findNamedCommand(const std::string &name)
{
    for (const auto &command : namedCommands)
    {
        if (command.name == name)
            return &command;
    }
    return nullptr;
}

bool isNamedField(const std::string &arg)
{
    for (const auto &command : namedCommands)
    {
        if (std::find(command.fields.begin(), command.fields.end(), arg) != command.fields.end())
            return true;
    }
    return false;
}

std::string signingOptionFor(const std::string &mode)
{
    if (mode == "setup" || mode == "setup_buffer")
        return "--with-signing-keys";
    if (mode == "encrypt" || mode == "encrypt_buffer")
        return "--sign";
    if (mode == "decrypt" || mode == "decrypt_buffer")
        return "--verify";
    return {};
}

bool appendNamedArguments(const std::string &mode, bool useSignature,
                          std::map<std::string, std::string> &fields, std::vector<std::string> &args)
{
    const auto *command = findNamedCommand(mode);
    if (!command || args.size() != 2)
    {
        std::cerr << "Use named arguments on their own with setup, genkey, encrypt, or decrypt.\n";
        return false;
    }

    if (mode == "setup" && fields.count("--output"))
    {
        if (fields.count("--file"))
        {
            std::cerr << "For setup, specify only one of --file and --output.\n";
            return false;
        }
        fields.emplace("--file", fields.at("--output"));
        fields.erase("--output");
    }

    for (const auto &field : command->fields)
    {
        if (field == command->signatureKeyField && !useSignature)
            continue;
        const auto value = fields.find(field);
        if (value == fields.end())
        {
            std::cerr << mode << " requires " << field << '\n';
            return false;
        }
        args.push_back(value->second);
        fields.erase(value);
    }
    if (!fields.empty())
    {
        if (fields.count(command->signatureKeyField))
            std::cerr << command->signatureKeyField << " requires " << signingOptionFor(mode) << '\n';
        else
            std::cerr << "Unknown argument for " << mode << ": " << fields.begin()->first << '\n';
        return false;
    }
    return true;
}

void printEncryptionOptions()
{
    std::cout << "  --scheme NAME     ac17 (default), tkn20, or covercrypt\n"
                 "  --aes-bits BITS   128, 192, or 256 (default) when encrypting\n"
                 "  --ml-dsa SET      44, 65, or 87 (default). Match the signing key's parameter set.\n";
}

void printCovercryptHelp(std::ostream &out = std::cout)
{
    out << "CoverCrypt setup\n"
                 "  Set HCPABE_COVERCRYPT_CONFIG to a dimensions JSON file.\n"
                 "  Example: scripts/covercrypt-demo.json. The CLI does not load .env files.\n"
                 "  HCPABE_COVERCRYPT_MODE: hybridized (default), post_quantum, or classic.\n"
                 "  Post-quantum modes use ML-KEM-768.\n";
}

void printCommandUsage(const CommandHelp &command, std::ostream &out)
{
    out << "Usage: " << cliName << ' ';
    if (const auto *named = findNamedCommand(command.name))
        out << "--" << command.name << ' ' << named->syntax << "\n   or: " << cliName << ' ';
    out << command.name;
    if (*command.syntax)
        out << ' ' << command.syntax;
    out << '\n';
}

int invalidCommandArguments(const std::string &name)
{
    for (const auto &command : commands)
    {
        if (name == command.name)
        {
            printCommandUsage(command, std::cerr);
            break;
        }
    }
    return 1;
}

bool printCommandHelp(const std::string &name)
{
    for (const auto &command : commands)
    {
        if (name != command.name)
            continue;
        printCommandUsage(command, std::cout);
        std::cout << '\n' << command.description << '\n';
        if (name == "setup")
            std::cout << "  --file sets the output directory or key file prefix (--output is an alias).\n"
                         "  --with-signing-keys writes ml-dsa_sk.key and ml-dsa_pk.key with the chosen prefix.\n";
        if (name == "encrypt" || name == "encrypt_buffer")
        {
            std::cout << "\nEncryption options\n";
            printEncryptionOptions();
        }
        if (name == "setup" || name == "setup_buffer")
        {
            std::cout << "  --with-signing-keys generates an ML-DSA key pair (default set: 87).\n\n";
            printCovercryptHelp();
        }
        return true;
    }
    return false;
}

void printUsage()
{
    std::cout << cliName << ' ' << getVersion() << " | PQ-CP-ABE\n\n"
              << "Usage: pq-cp-abe <command> [options] [arguments]\n\n"
                 "Commands\n"
                 "  Keys         setup, genkey (also --setup, --genkey)\n"
                 "  Files        encrypt, decrypt (also --encrypt, --decrypt)\n"
                 "  Buffers      setup_buffer, genkey_buffer, encrypt_buffer, decrypt_buffer\n"
                 "  CoverCrypt   add_dimension, add_attribute\n"
                 "  Info         version, help\n\n"
                 "Options\n";
    printEncryptionOptions();
    std::cout << "  -h, --help        Show help. Use <command> --help for arguments.\n"
                 "  -v, --version     Show the library version\n\n";
    std::cout << "Signature options\n"
                 "  setup    --with-signing-keys  Generate an ML-DSA key pair\n"
                 "  encrypt  --sign               Sign the data before encryption\n"
                 "  decrypt  --verify             Require a valid ML-DSA signature\n"
                 "  --ml-dsa selects the set with --with-signing-keys or --sign.\n\n";
    printCovercryptHelp();
    std::cout << "\nCoverCrypt example\n"
                 "  Set HCPABE_COVERCRYPT_CONFIG to scripts/covercrypt-demo.json and create data.txt.\n"
                 "  pq-cp-abe --setup --scheme covercrypt --file demo\n"
                 "  pq-cp-abe --genkey --scheme covercrypt --master-key demo_msk.key --attributes \"Department::IT && Level::ADMIN\" --user-key user.key\n"
                 "  pq-cp-abe --encrypt --scheme covercrypt --public-key demo_pk.key --file data.txt --policy \"Department::IT && Level::ADMIN\" --ciphertext data.enc\n"
                 "  pq-cp-abe --decrypt --user-key user.key --ciphertext data.enc --output recovered.txt\n";
}
}

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        printUsage();
        return 1;
    }

    std::vector<std::string> args{argv[0]};
    std::map<std::string, std::string> namedFields;
    bool legacyPqc = false;
    std::string signingOption;
    int aes_bits = 256, ml_dsa = 87;
    bool explicit_aes = false, explicit_dsa = false;
    CPABEScheme scheme = CPABE_SCHEME_AC17;

    for (int i = 1; i < argc; ++i)
    {
        std::string arg = argv[i];
        if (arg == "--pqc")
        {
            legacyPqc = true;
        }
        else if (arg == "--with-signing-keys" || arg == "--sign" || arg == "--verify")
        {
            if (!signingOption.empty() && signingOption != arg)
            {
                std::cerr << "Choose one signature action per command.\n";
                return 1;
            }
            signingOption = arg;
        }
        else if (arg == "--aes-bits" || arg == "--ml-dsa")
        {
            if (i + 1 >= argc) { std::cerr << arg << " requires a value\n"; return 1; }
            const std::string value = argv[++i];
            if (arg == "--aes-bits") {
                if (value != "128" && value != "192" && value != "256") {
                    std::cerr << "AES bits must be 128, 192 or 256\n"; return 1;
                }
                aes_bits = std::stoi(value); explicit_aes = true;
            } else {
                if (value != "44" && value != "65" && value != "87") {
                    std::cerr << "ML-DSA parameter set must be 44, 65 or 87\n"; return 1;
                }
                ml_dsa = std::stoi(value); explicit_dsa = true;
            }
        }
        else if (arg == "--scheme")
        {
            if (i + 1 < argc)
            {
                std::string schemeName = argv[++i];
                std::transform(schemeName.begin(), schemeName.end(), schemeName.begin(), ::tolower);
                if (schemeName == "ac17")
                {
                    scheme = CPABE_SCHEME_AC17;
                }
                else if (schemeName == "tkn20")
                {
                    scheme = CPABE_SCHEME_TKN20;
                }
                else if (schemeName == "covercrypt")
                {
                    scheme = CPABE_SCHEME_COVERCRYPT;
                }
                else
                {
                    std::cerr << "Error: Unknown scheme '" << schemeName << "'. Supported: ac17, tkn20, covercrypt." << std::endl;
                    return 1;
                }
            }
            else
            {
                std::cerr << "Error: --scheme requires an argument." << std::endl;
                return 1;
            }
        }
        else if (args.size() == 1 && arg.compare(0, 2, "--") == 0 &&
                 findNamedCommand(arg.substr(2)))
        {
            args.push_back(arg.substr(2));
        }
        else if (args.size() >= 2 && findNamedCommand(args[1]) && isNamedField(arg))
        {
            if (i + 1 >= argc || std::strncmp(argv[i + 1], "--", 2) == 0)
            {
                std::cerr << arg << " requires a value\n";
                return invalidCommandArguments(args[1]);
            }
            if (!namedFields.emplace(arg, argv[++i]).second)
            {
                std::cerr << arg << " was specified more than once\n";
                return invalidCommandArguments(args[1]);
            }
        }
        else
        {
            args.push_back(arg);
        }
    }

    if (args.size() < 2)
    {
        printUsage();
        return 1;
    }

    const std::string mode = args[1];
    const auto isHelp = [](const std::string &value) {
        return value == "-h" || value == "--help";
    };
    if (mode == "help" || isHelp(mode) || (args.size() == 3 && isHelp(args[2])))
    {
        if (args.size() == 2)
        {
            printUsage();
            return 0;
        }
        if (args.size() == 3)
        {
            const auto &command = isHelp(args[2]) ? mode : args[2];
            if (printCommandHelp(command))
                return 0;
            std::cerr << "Unknown command: " << command << '\n';
        }
        else
            std::cerr << "Usage: pq-cp-abe help [command]\n";
        return 1;
    }

    std::vector<std::string> reserved_commands = {"setup", "genkey", "encrypt", "decrypt", "setup_buffer", "genkey_buffer", "encrypt_buffer", "decrypt_buffer", "add_dimension", "add_attribute"};
    for (size_t i = 2; i < args.size(); ++i)
    {
        if (std::find(reserved_commands.begin(), reserved_commands.end(), args[i]) != reserved_commands.end())
        {
            std::cerr << "Error: You used a reserved command name '" << args[i] << "' as an argument." << std::endl;
            return 1;
        }
    }

    const std::string expectedSigningOption = signingOptionFor(mode);
    if (!signingOption.empty() && signingOption != expectedSigningOption)
    {
        std::cerr << signingOption << " is not valid for " << mode << ".\n";
        return invalidCommandArguments(mode);
    }
    const bool useSignature = legacyPqc || !signingOption.empty();
    if (!namedFields.empty() && !appendNamedArguments(mode, useSignature, namedFields, args))
        return invalidCommandArguments(mode);

    if (mode == "-v" || mode == "--version" || mode == "version")
    {
        std::cout << "Hybrid PQ-CP-ABE Library v" << getVersion() << std::endl;
        return 0;
    }

    int result = HCPABE_SUCCESS;
    if (explicit_aes && expectedSigningOption != "--sign")
    {
        std::cerr << "--aes-bits is for encryption. Decryption detects the key size.\n";
        return invalidCommandArguments(mode);
    }
    if (explicit_dsa && (!useSignature || (expectedSigningOption != "--with-signing-keys" &&
                                           expectedSigningOption != "--sign")))
    {
        std::cerr << "--ml-dsa requires --with-signing-keys on setup or --sign on encryption.\n";
        return invalidCommandArguments(mode);
    }

    try
    {
        if (mode == "setup")
        {
            if (args.size() != 3)
            {
                const int status = invalidCommandArguments(mode);
                if (scheme == CPABE_SCHEME_COVERCRYPT)
                    printCovercryptHelp(std::cerr);
                return status;
            }
            if (signingOption == "--with-signing-keys")
            {
                result = setup_with_ml_dsa_files(args[2].c_str(), scheme, ml_dsa, "ml-dsa");
            }
            else if (useSignature)
            {
                result = explicit_dsa
                    ? hybrid_cpabe_setup_with_ml_dsa(args[2].c_str(), scheme, ml_dsa)
                    : hybrid_cpabe_setup_with_pqc_scheme(args[2].c_str(), scheme);
            }
            else
            {
                result = setup_with_scheme(args[2].c_str(), scheme);
            }
        }
        else if (mode == "add_dimension" || mode == "add_attribute")
        {
            if (scheme != CPABE_SCHEME_COVERCRYPT || useSignature)
            {
                std::cerr << "Authority growth requires --scheme covercrypt and takes no signature options.\n";
                return 1;
            }
            if (mode == "add_dimension")
            {
                if (args.size() != 5)
                {
                    std::cerr << "Usage: " << args[0] << " add_dimension --scheme covercrypt <msk> <dimension_json_file> <new_prefix>" << std::endl;
                    return 1;
                }
                std::ifstream file(args[3], std::ios::binary);
                if (!file)
                {
                    std::cerr << "Cannot read dimension JSON: " << args[3] << std::endl;
                    return 1;
                }
                std::ostringstream json;
                json << file.rdbuf();
                result = hybrid_cpabe_covercrypt_add_dimension(args[2].c_str(), json.str().c_str(), args[4].c_str());
            }
            else
            {
                if (args.size() != 6 && args.size() != 7)
                {
                    std::cerr << "Usage: " << args[0] << " add_attribute --scheme covercrypt <msk> <dimension> <attribute> <new_prefix> [after_attribute]" << std::endl;
                    return 1;
                }
                result = hybrid_cpabe_covercrypt_add_attribute(args[2].c_str(), args[3].c_str(), args[4].c_str(),
                                                               args.size() == 7 ? args[6].c_str() : nullptr, args[5].c_str());
            }
        }
        else if (mode == "genkey")
        {
            if (args.size() != 5)
                return invalidCommandArguments(mode);
            result = generateSecretKey_with_scheme(args[2].c_str(), args[3].c_str(), args[4].c_str(), scheme);
        }
        else if (mode == "encrypt")
        {
            if (args.size() != (useSignature ? 7 : 6))
                return invalidCommandArguments(mode);
            if (useSignature)
            {
                result = (explicit_aes || explicit_dsa)
                    ? hybrid_cpabe_encrypt_and_sign_with_params(args[2].c_str(), args[3].c_str(), args[4].c_str(), args[5].c_str(), args[6].c_str(), scheme, aes_bits, ml_dsa)
                    : hybrid_cpabe_encrypt_and_sign_with_scheme(args[2].c_str(), args[3].c_str(), args[4].c_str(), args[5].c_str(), args[6].c_str(), scheme);
            }
            else
            {
                result = explicit_aes
                    ? hybrid_cpabe_encrypt_with_params(args[2].c_str(), args[3].c_str(), args[4].c_str(), args[5].c_str(), scheme, aes_bits)
                    : hybrid_cpabe_encrypt_with_scheme(args[2].c_str(), args[3].c_str(), args[4].c_str(), args[5].c_str(), scheme);
            }
        }
        else if (mode == "decrypt")
        {
            if (args.size() != (useSignature ? 6 : 5))
                return invalidCommandArguments(mode);
            if (useSignature)
            {
                result = hybrid_cpabe_decrypt_and_verify(args[2].c_str(), args[3].c_str(), args[4].c_str(), args[5].c_str());
            }
            else
            {
                result = hybrid_cpabe_decrypt(args[2].c_str(), args[3].c_str(), args[4].c_str());
            }
        }
        else if (mode == "encrypt_buffer")
        {
            if (useSignature)
            {
                if (args.size() != 7)
                    return invalidCommandArguments(mode);
                std::ifstream pkFile(args[2], std::ios::binary);
                if (!pkFile)
                    return 1;
                std::string pkStr((std::istreambuf_iterator<char>(pkFile)), std::istreambuf_iterator<char>());
                pkFile.close();
                std::string decodedPkStr;
                CryptoPP::StringSource(pkStr, true, new CryptoPP::Base64Decoder(new CryptoPP::StringSink(decodedPkStr)));

                std::ifstream mskFile(args[3], std::ios::binary);
                if (!mskFile)
                    return 1;
                std::string mskStr((std::istreambuf_iterator<char>(mskFile)), std::istreambuf_iterator<char>());
                mskFile.close();
                std::string decodedMskStr;
                CryptoPP::StringSource(mskStr, true, new CryptoPP::Base64Decoder(new CryptoPP::StringSink(decodedMskStr)));

                std::string ptStr = args[4];
                unsigned char *ct = nullptr;
                size_t ctLen = 0;

                if (explicit_aes || explicit_dsa) result = hybrid_cpabe_encryptBuffer_and_sign_with_params(
                    (const unsigned char *)decodedPkStr.data(), decodedPkStr.size(),
                    (const unsigned char *)decodedMskStr.data(), decodedMskStr.size(),
                    (const unsigned char *)ptStr.data(), ptStr.size(),
                    args[5].c_str(), &ct, &ctLen, scheme, aes_bits, ml_dsa);
                else result = hybrid_cpabe_encryptBuffer_and_sign_with_scheme(
                    (const unsigned char *)decodedPkStr.data(), decodedPkStr.size(),
                    (const unsigned char *)decodedMskStr.data(), decodedMskStr.size(),
                    (const unsigned char *)ptStr.data(), ptStr.size(),
                    args[5].c_str(), &ct, &ctLen, scheme);
                if (result == HCPABE_SUCCESS)
                {
                    std::ofstream outFile(args[6], std::ios::binary);
                    outFile.write((char *)ct, ctLen);
                    outFile.close();
                    freeBuffer(ct);
                }
            }
            else
            {
                if (args.size() != 6)
                    return invalidCommandArguments(mode);
                std::ifstream pkFile(args[2], std::ios::binary);
                if (!pkFile)
                {
                    std::cerr << "Cannot open public key file." << std::endl;
                    return 1;
                }
                std::string pkStr((std::istreambuf_iterator<char>(pkFile)), std::istreambuf_iterator<char>());
                pkFile.close();

                std::string decodedPkStr;
                CryptoPP::StringSource(pkStr, true, new CryptoPP::Base64Decoder(new CryptoPP::StringSink(decodedPkStr)));

                std::string ptStr = args[3];
                unsigned char *ct = nullptr;
                size_t ctLen = 0;

                if (explicit_aes) result = hybrid_cpabe_encryptBuffer_with_params(
                    (const unsigned char *)decodedPkStr.data(), decodedPkStr.size(),
                    (const unsigned char *)ptStr.data(), ptStr.size(), args[4].c_str(), &ct, &ctLen, scheme, aes_bits);
                else result = hybrid_cpabe_encryptBuffer_with_scheme((const unsigned char *)decodedPkStr.data(), decodedPkStr.size(),
                                                                (const unsigned char *)ptStr.data(), ptStr.size(),
                                                                args[4].c_str(), &ct, &ctLen, scheme);
                if (result == HCPABE_SUCCESS)
                {
                    std::ofstream outFile(args[5], std::ios::binary);
                    outFile.write((char *)ct, ctLen);
                    outFile.close();
                    freeBuffer(ct);
                }
            }
        }
        else if (mode == "decrypt_buffer")
        {
            if (useSignature)
            {
                if (args.size() != 5)
                    return invalidCommandArguments(mode);
                std::ifstream skFile(args[2], std::ios::binary);
                if (!skFile)
                    return 1;
                std::string skStr((std::istreambuf_iterator<char>(skFile)), std::istreambuf_iterator<char>());
                skFile.close();
                std::string decodedSkStr;
                CryptoPP::StringSource(skStr, true, new CryptoPP::Base64Decoder(new CryptoPP::StringSink(decodedSkStr)));

                std::ifstream pkFile(args[3], std::ios::binary);
                if (!pkFile)
                    return 1;
                std::string pkStr((std::istreambuf_iterator<char>(pkFile)), std::istreambuf_iterator<char>());
                pkFile.close();
                std::string decodedPkStr;
                CryptoPP::StringSource(pkStr, true, new CryptoPP::Base64Decoder(new CryptoPP::StringSink(decodedPkStr)));

                std::ifstream ctFile(args[4], std::ios::binary);
                if (!ctFile)
                    return 1;
                std::string ctStr((std::istreambuf_iterator<char>(ctFile)), std::istreambuf_iterator<char>());
                ctFile.close();

                unsigned char *pt = nullptr;
                size_t ptLen = 0;

                result = hybrid_cpabe_decryptBuffer_and_verify(
                    (const unsigned char *)decodedSkStr.data(), decodedSkStr.size(),
                    (const unsigned char *)decodedPkStr.data(), decodedPkStr.size(),
                    (const unsigned char *)ctStr.data(), ctStr.size(),
                    &pt, &ptLen);
                if (result == HCPABE_SUCCESS)
                {
                    std::string ptOut((char *)pt, ptLen);
                    std::cout << "Decrypted Buffer: " << ptOut << std::endl;
                    freeBuffer(pt);
                }
            }
            else
            {
                if (args.size() != 4)
                    return invalidCommandArguments(mode);
                std::ifstream skFile(args[2], std::ios::binary);
                if (!skFile)
                {
                    std::cerr << "Cannot open private key file." << std::endl;
                    return 1;
                }
                std::string skStr((std::istreambuf_iterator<char>(skFile)), std::istreambuf_iterator<char>());
                skFile.close();

                std::string decodedSkStr;
                CryptoPP::StringSource(skStr, true, new CryptoPP::Base64Decoder(new CryptoPP::StringSink(decodedSkStr)));

                std::ifstream ctFile(args[3], std::ios::binary);
                if (!ctFile)
                {
                    std::cerr << "Cannot open ciphertext file." << std::endl;
                    return 1;
                }
                std::string ctStr((std::istreambuf_iterator<char>(ctFile)), std::istreambuf_iterator<char>());
                ctFile.close();

                unsigned char *pt = nullptr;
                size_t ptLen = 0;

                result = hybrid_cpabe_decryptBuffer((const unsigned char *)decodedSkStr.data(), decodedSkStr.size(),
                                                    (const unsigned char *)ctStr.data(), ctStr.size(),
                                                    &pt, &ptLen);
                if (result == HCPABE_SUCCESS)
                {
                    std::string ptOut((char *)pt, ptLen);
                    std::cout << "Decrypted Buffer: " << ptOut << std::endl;
                    freeBuffer(pt);
                }
            }
        }
        else if (mode == "setup_buffer")
        {
            if (useSignature)
            {
                unsigned char *abePk = nullptr;
                size_t abePkLen = 0;
                unsigned char *abeMsk = nullptr;
                size_t abeMskLen = 0;
                unsigned char *pqcPk = nullptr;
                size_t pqcPkLen = 0;
                unsigned char *pqcMsk = nullptr;
                size_t pqcMskLen = 0;

                result = explicit_dsa
                    ? hybrid_cpabe_setupBuffer_with_ml_dsa(&abePk, &abePkLen, &abeMsk, &abeMskLen, &pqcPk, &pqcPkLen, &pqcMsk, &pqcMskLen, scheme, ml_dsa)
                    : hybrid_cpabe_setupBuffer_with_pqc_scheme(&abePk, &abePkLen, &abeMsk, &abeMskLen, &pqcPk, &pqcPkLen, &pqcMsk, &pqcMskLen, scheme);
                if (result == HCPABE_SUCCESS)
                {
                    std::string pkBase64, mskBase64, pqcPkBase64, pqcMskBase64;
                    CryptoPP::StringSource(abePk, abePkLen, true, new CryptoPP::Base64Encoder(new CryptoPP::StringSink(pkBase64), false));
                    CryptoPP::StringSource(abeMsk, abeMskLen, true, new CryptoPP::Base64Encoder(new CryptoPP::StringSink(mskBase64), false));
                    CryptoPP::StringSource(pqcPk, pqcPkLen, true, new CryptoPP::Base64Encoder(new CryptoPP::StringSink(pqcPkBase64), false));
                    CryptoPP::StringSource(pqcMsk, pqcMskLen, true, new CryptoPP::Base64Encoder(new CryptoPP::StringSink(pqcMskBase64), false));

                    std::cout << "--- PUBLIC KEY (Base64) ---" << std::endl
                              << pkBase64 << std::endl;
                    std::cout << "--- MASTER SECRET KEY (Base64) ---" << std::endl
                              << mskBase64 << std::endl;
                    std::cout << "--- PQC PUBLIC KEY (Base64) ---" << std::endl
                              << pqcPkBase64 << std::endl;
                    std::cout << "--- PQC SECRET KEY (Base64) ---" << std::endl
                              << pqcMskBase64 << std::endl;

                    freeBuffer(abePk);
                    freeBuffer(abeMsk);
                    freeBuffer(pqcPk);
                    freeBuffer(pqcMsk);
                }
            }
            else
            {
                unsigned char *pk = nullptr;
                size_t pkLen = 0;
                unsigned char *msk = nullptr;
                size_t mskLen = 0;

                result = hybrid_cpabe_setupBuffer_with_scheme(&pk, &pkLen, &msk, &mskLen, scheme);
                if (result == HCPABE_SUCCESS)
                {
                    std::string pkBase64;
                    CryptoPP::StringSource(pk, pkLen, true, new CryptoPP::Base64Encoder(new CryptoPP::StringSink(pkBase64), false));
                    std::string mskBase64;
                    CryptoPP::StringSource(msk, mskLen, true, new CryptoPP::Base64Encoder(new CryptoPP::StringSink(mskBase64), false));
                    std::cout << "--- PUBLIC KEY (Base64) ---" << std::endl
                              << pkBase64 << std::endl;
                    std::cout << "--- MASTER SECRET KEY (Base64) ---" << std::endl
                              << mskBase64 << std::endl;
                    freeBuffer(pk);
                    freeBuffer(msk);
                }
            }
        }
        else if (mode == "genkey_buffer")
        {
            if (args.size() != 4)
            {
                std::cerr << "Usage: " << args[0] << " genkey_buffer [--scheme <name>] <master_key_file> <attributes>" << std::endl;
                return 1;
            }
            std::ifstream mskFile(args[2], std::ios::binary);
            if (!mskFile)
            {
                std::cerr << "Cannot open MSK file." << std::endl;
                return 1;
            }
            std::string mskStr((std::istreambuf_iterator<char>(mskFile)), std::istreambuf_iterator<char>());
            mskFile.close();

            std::string decodedMskStr;
            CryptoPP::StringSource(mskStr, true, new CryptoPP::Base64Decoder(new CryptoPP::StringSink(decodedMskStr)));

            unsigned char *sk = nullptr;
            size_t skLen = 0;

            result = hybrid_cpabe_genkeyBuffer_with_scheme((const unsigned char *)decodedMskStr.data(), decodedMskStr.size(), args[3].c_str(), &sk, &skLen, scheme);
            if (result == HCPABE_SUCCESS)
            {
                std::string skBase64;
                CryptoPP::StringSource(sk, skLen, true, new CryptoPP::Base64Encoder(new CryptoPP::StringSink(skBase64), false));
                std::cout << "--- SECRET KEY (Base64) ---" << std::endl
                          << skBase64 << std::endl;
                freeBuffer(sk);
            }
        }
        else
        {
            std::cerr << "Error: Invalid command '" << mode << "'" << std::endl;
            std::cerr << "Use '" << args[0] << " --help' for usage information." << std::endl;
            return 1;
        }

        if (result != HCPABE_SUCCESS)
        {
            std::cerr << "Operation failed: " << getErrorMessage(result) << " (code: " << result << ")" << std::endl;
            if (scheme == CPABE_SCHEME_COVERCRYPT && (mode == "setup" || mode == "setup_buffer"))
            {
                std::cerr << "Covercrypt setup requires HCPABE_COVERCRYPT_CONFIG (dimensions JSON); "
                          << "check HCPABE_COVERCRYPT_MODE as well. Use --help for scripts/covercrypt-demo.json examples."
                          << std::endl;
            }
        }
        else if (scheme == CPABE_SCHEME_COVERCRYPT)
        {
            // Legacy setup --pqc already reports success when it uses the default parameter set.
            if (mode == "setup" && (!legacyPqc || explicit_dsa || !signingOption.empty()))
                std::cout << "CoverCrypt setup successful!\n";
            else if (mode == "genkey")
                std::cout << "User key generated successfully: " << args[4] << '\n';
        }
    }
    catch (const std::exception &ex)
    {
        std::cerr << "Exception: " << ex.what() << std::endl;
        return 1;
    }

    return (result == HCPABE_SUCCESS) ? 0 : 1;
}
