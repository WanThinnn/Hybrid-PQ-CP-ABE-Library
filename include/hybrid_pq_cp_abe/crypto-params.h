#ifndef HCPABE_CRYPTO_PARAMS_H
#define HCPABE_CRYPTO_PARAMS_H

/* Standalone C/C++ entry point for the parameterized APIs. The umbrella header
 * supplies their LIB_API declarations and all legacy declarations as well.
 * Integer-valued C ABI arguments accept these enum constants without changing
 * existing ABI layouts. ML-DSA/ML-KEM suffixes name parameter sets, not bits.
 */
#include "hybrid-pq-cp-abe.h"

typedef enum {
    HCPABE_AES_128 = 128,
    HCPABE_AES_192 = 192,
    HCPABE_AES_256 = 256
} HCPABEAesKeyBits;

typedef enum {
    HCPABE_ML_DSA_44 = 44,
    HCPABE_ML_DSA_65 = 65,
    HCPABE_ML_DSA_87 = 87
} HCPABEMlDsaParameterSet;

typedef enum {
    HCPABE_ML_KEM_512 = 512,
    HCPABE_ML_KEM_768 = 768,
    HCPABE_ML_KEM_1024 = 1024
} HCPABEMlKemParameterSet;

enum {
    HCPABE_DEFAULT_AES_BITS = HCPABE_AES_256,
    HCPABE_DEFAULT_ML_DSA = HCPABE_ML_DSA_87,
    HCPABE_COVERCRYPT_ML_KEM = HCPABE_ML_KEM_768
};

#endif
