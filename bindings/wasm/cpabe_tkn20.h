#pragma once
#include <stddef.h>
#include <stdint.h>
extern "C" {
typedef struct { uint8_t *data; size_t len; } CByteArray;
void TKN20_FreeByteArray(CByteArray);
int TKN20_Setup(CByteArray *, CByteArray *);
int TKN20_KeyGen(uint8_t *, size_t, char *, CByteArray *);
int TKN20_Encrypt(uint8_t *, size_t, char *, uint8_t *, size_t, CByteArray *);
int TKN20_Decrypt(uint8_t *, size_t, uint8_t *, size_t, CByteArray *);
}
