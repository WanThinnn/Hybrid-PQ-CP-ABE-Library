/* This header must be usable by C FFI consumers, including repeated inclusion. */
#include "hybrid_pq_cp_abe/crypto-params.h"
#include "hybrid_pq_cp_abe/crypto-params.h"
#include "hybrid_pq_cp_abe/hybrid-pq-cp-abe.h"
typedef char default_aes_is_256[(HCPABE_DEFAULT_AES_BITS == 256) ? 1 : -1];
typedef char default_dsa_is_87[(HCPABE_DEFAULT_ML_DSA == 87) ? 1 : -1];
typedef char covercrypt_is_768[(HCPABE_COVERCRYPT_ML_KEM == 768) ? 1 : -1];
int check_parameter_header(void) {
    int (*provider)(void) = hybrid_cpabe_covercrypt_ml_kem_parameter_set;
    return provider() == HCPABE_ML_KEM_768;
}
