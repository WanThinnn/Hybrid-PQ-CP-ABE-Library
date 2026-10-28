#ifndef HYBRID_COVERCRYPT_FFI_H
#define HYBRID_COVERCRYPT_FFI_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C"
{
#endif

    enum
    {
        CC_OK = 0,
        CC_INVALID_INPUT = -1,
        CC_ERROR = -2,
        CC_ACCESS_DENIED = -3,
        CC_PANIC = -4
    };
    enum
    {
        CC_CLASSIC = 0,
        CC_POST_QUANTUM = 1,
        CC_HYBRIDIZED = 2
    };
    typedef struct
    {
        uint8_t *data;
        size_t len;
    } cc_buffer;

    /* All pointers must reference valid memory; text is NUL-terminated ASCII.
     * Output structs must be distinct and initialized to {NULL, 0}.
     * Free only original bridge-owned buffers with cc_buffer_free (never free/delete).
     * Serialized keys/encapsulations are opaque and use CoverCrypt v16 formats.
     * KEM operations generate/recover a 32-byte shared secret, not a data ciphertext.
     * Build configuration: Curve25519 provider + ML-KEM-768.
     */
    int cc_setup(const char *dimensions_json, int mode, cc_buffer *msk, cc_buffer *mpk);
    /* Adds one attribute to an existing authority and returns the updated MSK/MPK.
     * after_or_null is only relevant for hierarchical dimensions; pass NULL otherwise. */
    int cc_add_attribute(const uint8_t *msk, size_t msk_len,
                         const char *dimension, const char *attribute, int mode,
                         const char *after_or_null, cc_buffer *updated_msk, cc_buffer *updated_mpk);
    /* Persist updated_msk on success: key generation updates upstream authority state. */
    int cc_genkey(const uint8_t *msk, size_t msk_len, const char *policy,
                  cc_buffer *updated_msk, cc_buffer *usk);
    int cc_encaps(const uint8_t *mpk, size_t mpk_len, const char *policy,
                  cc_buffer *secret, cc_buffer *encapsulation);
    int cc_decaps(const uint8_t *usk, size_t usk_len,
                  const uint8_t *encapsulation, size_t encapsulation_len, cc_buffer *secret);
    void cc_buffer_free(cc_buffer *buffer);
    /* Thread-local diagnostic, valid until the next operation on this thread. */
    const char *cc_last_error(void);

#ifdef __cplusplus
}
#endif
#endif
