#ifndef CPABE_SCHEME_H
#define CPABE_SCHEME_H

#ifdef __cplusplus
#include <cstddef>
#include <cstdint>
#else
#include <stddef.h>
#include <stdint.h>
#endif

// ============================================================================
// CP-ABE Scheme Selection
// ============================================================================

typedef enum {
    CPABE_SCHEME_AC17 = 0,   // AC17 scheme (rabe-ffi, Rust)
    CPABE_SCHEME_TKN20 = 1   // TKN20 scheme (CIRCL, Go)
} CPABEScheme;

// ============================================================================
// AC17 Scheme Operations (implemented in ac17.cpp)
// ============================================================================

int ac17_setup(const char *path);
int ac17_setupBuffer(unsigned char **pkBuffer, size_t *pkLen, unsigned char **mskBuffer, size_t *mskLen);
int ac17_genkey(const char *mskFile, const char *attrs, const char *skFile);
int ac17_genkeyBuffer(const unsigned char *mskBuffer, size_t mskLen, const char *attrs, unsigned char **skBuffer, size_t *skLen);

int ac17_encapsulate_key(
    const unsigned char *pkData, size_t pkLen,
    const char *policy,
    const unsigned char *plaintext, size_t ptLen,
    unsigned char **ciphertext, size_t *ctLen);

int ac17_decapsulate_key(
    const unsigned char *skData, size_t skLen,
    const unsigned char *ciphertext, size_t ctLen,
    unsigned char **plaintext, size_t *ptLen);

int ac17_load_pk(const char *file, unsigned char **pkData, size_t *pkLen);
int ac17_load_sk(const char *file, unsigned char **skData, size_t *skLen);

// ============================================================================
// TKN20 Scheme Operations (implemented in tkn20.cpp)
// ============================================================================

int tkn20_setup(const char *path);
int tkn20_setupBuffer(unsigned char **pkBuffer, size_t *pkLen, unsigned char **mskBuffer, size_t *mskLen);
int tkn20_genkey(const char *mskFile, const char *attrs, const char *skFile);
int tkn20_genkeyBuffer(const unsigned char *mskBuffer, size_t mskLen, const char *attrs, unsigned char **skBuffer, size_t *skLen);

int tkn20_encapsulate_key(
    const unsigned char *pkData, size_t pkLen,
    const char *policy,
    const unsigned char *plaintext, size_t ptLen,
    unsigned char **ciphertext, size_t *ctLen);

int tkn20_decapsulate_key(
    const unsigned char *skData, size_t skLen,
    const unsigned char *ciphertext, size_t ctLen,
    unsigned char **plaintext, size_t *ptLen);

int tkn20_load_pk(const char *file, unsigned char **pkData, size_t *pkLen);
int tkn20_load_sk(const char *file, unsigned char **skData, size_t *skLen);

#endif // CPABE_SCHEME_H
