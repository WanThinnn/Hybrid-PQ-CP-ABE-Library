#include "cpabe_tkn20.h"
#include <cstdlib>
#include <emscripten.h>

// Go and Emscripten have independent memories. Copy at each ABI boundary.
EM_JS(int, tkn20_call, (int op, const uint8_t *a, size_t alen, const char *text,
                       const uint8_t *b, size_t blen, CByteArray *out, CByteArray *out2), {
    const allocated = [];
    HEAPU32[out >> 2] = 0; HEAPU32[(out + 4) >> 2] = 0;
    if (out2) { HEAPU32[out2 >> 2] = 0; HEAPU32[(out2 + 4) >> 2] = 0; }
    try {
        const result = Module['tkn20'](op, HEAPU8.slice(a, a + alen),
            text ? UTF8ToString(text) : "", HEAPU8.slice(b, b + blen));
        if (!result) return -1;
        const outputs = [out, out2];
        for (let i = 0; i < result.length; ++i) {
            const data = result[i];
            const ptr = _malloc(data.length || 1);
            if (!ptr) throw new Error('TKN20 allocation failed');
            allocated.push(ptr);
            HEAPU8.set(data, ptr);
            HEAPU32[outputs[i] >> 2] = ptr;
            HEAPU32[(outputs[i] + 4) >> 2] = data.length;
        }
        return 0;
    } catch (error) {
        for (const ptr of allocated) _free(ptr);
        HEAPU32[out >> 2] = 0; HEAPU32[(out + 4) >> 2] = 0;
        if (out2) { HEAPU32[out2 >> 2] = 0; HEAPU32[(out2 + 4) >> 2] = 0; }
        return -1;
    }
});
extern "C" {
void TKN20_FreeByteArray(CByteArray a) { free(a.data); }
int TKN20_Setup(CByteArray *pk, CByteArray *msk) {
    return tkn20_call(0, nullptr, 0, nullptr, nullptr, 0, pk, msk);
}
int TKN20_KeyGen(uint8_t *msk, size_t n, char *attrs, CByteArray *out) {
    return tkn20_call(1, msk, n, attrs, nullptr, 0, out, nullptr);
}
int TKN20_Encrypt(uint8_t *pk, size_t n, char *policy, uint8_t *msg, size_t m, CByteArray *out) {
    return tkn20_call(2, pk, n, policy, msg, m, out, nullptr);
}
int TKN20_Decrypt(uint8_t *sk, size_t n, uint8_t *ct, size_t m, CByteArray *out) {
    return tkn20_call(3, sk, n, nullptr, ct, m, out, nullptr);
}
}
