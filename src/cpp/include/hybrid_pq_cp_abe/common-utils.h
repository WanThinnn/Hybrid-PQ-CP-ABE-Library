#ifndef COMMON_UTILS_H
#define COMMON_UTILS_H

#include <string>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <algorithm>
#include <vector>
#include <sys/stat.h>

// Group of commonly used Crypto++ headers
#include <cryptopp/cryptlib.h>
#include <cryptopp/base64.h>
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>
#include <cryptopp/files.h>

inline void secureWipe(void* ptr, size_t len) {
    if (ptr == nullptr || len == 0) return;
    volatile unsigned char* p = static_cast<volatile unsigned char*>(ptr);
    while (len--) {
        *p++ = 0;
    }
}

inline bool SaveFile(const std::string &filename, const char *data, const std::string &format)
{
    if (data == nullptr)
    {
        std::cerr << "Error: Null data passed to SaveFile" << std::endl;
        return false;
    }
    size_t data_len = std::strlen(data);
    try
    {
        if (format == "JsonText" || format == "Original")
        {
            CryptoPP::FileSink file(filename.c_str(), true);
            file.Put(reinterpret_cast<const CryptoPP::byte *>(data), data_len);
            file.MessageEnd();
        }
        else if (format == "Base64")
        {
            CryptoPP::StringSource ss(reinterpret_cast<const CryptoPP::byte *>(data), data_len, true,
                new CryptoPP::Base64Encoder(new CryptoPP::FileSink(filename.c_str()), false));
        }
        else if (format == "HEX")
        {
            CryptoPP::StringSource ss(reinterpret_cast<const CryptoPP::byte *>(data), data_len, true,
                new CryptoPP::HexEncoder(new CryptoPP::FileSink(filename.c_str()), false));
        }
        else
        {
            std::cerr << "Unsupported format. Please choose 'JsonText', 'Base64', 'HEX' or 'Original'\n";
            return false;
        }
    }
    catch (const CryptoPP::Exception &ex)
    {
        std::cerr << "Crypto++ exception: " << ex.what() << std::endl;
        return false;
    }
    catch (const std::exception &ex)
    {
        std::cerr << "Standard exception: " << ex.what() << std::endl;
        return false;
    }
    return true;
}

inline bool LoadFile(const std::string &filename, std::string &data, const std::string &format)
{
    try
    {
        std::string encodedData;
        CryptoPP::FileSource fs(filename.c_str(), true, new CryptoPP::StringSink(encodedData));
        if (format == "Base64")
        {
            CryptoPP::StringSource ss(encodedData, true,
                new CryptoPP::Base64Decoder(new CryptoPP::StringSink(data)));
        }
        else if (format == "HEX")
        {
            CryptoPP::StringSource ss(encodedData, true,
                new CryptoPP::HexDecoder(new CryptoPP::StringSink(data)));
        }
        else if (format == "JsonText" || format == "Original")
        {
            data = encodedData;
        }
        else
        {
            std::cerr << "Unsupported format. Please choose 'Base64', 'HEX', 'JsonText', or 'Original'\n";
            return false;
        }
    }
    catch (const CryptoPP::Exception &e)
    {
        std::cerr << "CryptoPP Exception: " << e.what() << std::endl;
        return false;
    }
    return true;
}

// Convert string to lowercase
inline std::string toLowerCase(const std::string &str) {
    std::string lowerStr = str;
    std::transform(lowerStr.begin(), lowerStr.end(), lowerStr.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return lowerStr;
}

// Save binary data as Base64
inline bool SaveBinaryAsBase64(const std::string &filename, const unsigned char *data, size_t len) {
    try {
        CryptoPP::StringSource ss(data, len, true,
            new CryptoPP::Base64Encoder(new CryptoPP::FileSink(filename.c_str()), false));
        return true;
    } catch (const std::exception &e) {
        std::cerr << "SaveBinaryAsBase64 error: " << e.what() << std::endl;
        return false;
    }
}

#endif // COMMON_UTILS_H
