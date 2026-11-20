#pragma once
#include "hybrid_pq_cp_abe/hybrid-pq-cp-abe.h"
#include <oqs/oqs.h>
#include <cstdlib>
#include <memory>

namespace pqc
{
    struct WipeFree
    {
        size_t size;
        void operator()(unsigned char *p) const
        {
            if (p)
                OQS_MEM_secure_free(p, size);
        }
    };
    using Bytes = std::unique_ptr<unsigned char, WipeFree>;
    inline Bytes allocate(size_t size)
    {
        return Bytes(static_cast<unsigned char *>(std::malloc(size)), WipeFree{size});
    }
    inline bool output(unsigned char **p, size_t *n)
    {
        if (p)
            *p = nullptr;
        if (n)
            *n = 0;
        return p && n;
    }
    inline bool outputs(unsigned char **a, size_t *an, unsigned char **b, size_t *bn)
    {
        const bool first = output(a, an), second = output(b, bn);
        return first && second && a != b && an != bn;
    }
    inline const char *signature_name(int parameter)
    {
        switch (parameter)
        {
        case 44:
            return OQS_SIG_alg_ml_dsa_44;
        case 65:
            return OQS_SIG_alg_ml_dsa_65;
        case 87:
            return OQS_SIG_alg_ml_dsa_87;
        default:
            return nullptr;
        }
    }
    inline const char *kem_name(int parameter)
    {
        switch (parameter)
        {
        case 512:
            return OQS_KEM_alg_ml_kem_512;
        case 768:
            return OQS_KEM_alg_ml_kem_768;
        case 1024:
            return OQS_KEM_alg_ml_kem_1024;
        default:
            return nullptr;
        }
    }
    using Signature = std::unique_ptr<OQS_SIG, decltype(&OQS_SIG_free)>;
    using Kem = std::unique_ptr<OQS_KEM, decltype(&OQS_KEM_free)>;
    inline Signature signature(int parameter)
    {
        const auto name = signature_name(parameter);
        return Signature(name ? OQS_SIG_new(name) : nullptr, OQS_SIG_free);
    }
    inline Kem kem(int parameter)
    {
        const auto name = kem_name(parameter);
        return Kem(name ? OQS_KEM_new(name) : nullptr, OQS_KEM_free);
    }
}
