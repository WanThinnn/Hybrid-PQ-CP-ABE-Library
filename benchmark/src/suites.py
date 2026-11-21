from __future__ import annotations

import os
import statistics
from .config import (SCHEMES, COVERCRYPT, NATIVE_SCHEMES, adaptive_iterations,
                     attrs_for, policy_for, covercrypt_policy_attrs)
from .records import add
from .reports import human_bytes
from .timing import measure

def run_native_comparison(native, rec, scheme, policy, attrs, policy_count, n, warm, quiet):
    name = SCHEMES[scheme]
    secret = bytes(range(32))
    samples, pair = measure(
        lambda: native.backend(scheme).setup(), n, warm, quiet,
        f"{name} / Primitive / Setup"
    )
    add(rec, samples, "primitive_compare", name, "native", "hybrid_32_bytes",
        "setup", "32-byte key material", len(secret), policy_count)
    pk, msk = pair

    samples, sk = measure(
        lambda: native.backend(scheme).keygen(msk, attrs), n, warm, quiet,
        f"{name} / Primitive / KeyGen"
    )
    add(rec, samples, "primitive_compare", name, "native", "hybrid_32_bytes",
        "keygen", "32-byte key material", len(secret), policy_count)

    samples, ct = measure(
        lambda: native.backend(scheme).encrypt(pk, secret, policy), n, warm, quiet,
        f"{name} / Primitive / Protect"
    )
    extra = {"ciphertext_bytes": len(ct), "key_material_bytes": len(secret)}
    if scheme == COVERCRYPT:
        extra.update({
            "covercrypt_mode": "hybridized",
            "adapter_semantics": "Python CoverCryptABE hybrid encryption of 32 bytes",
        })
    add(rec, samples, "primitive_compare", name, "native", "hybrid_32_bytes",
        "protect", "32-byte key material", len(secret), policy_count, extra)

    samples, recovered = measure(
        lambda: native.api.decrypt(sk, ct), n, warm, quiet,
        f"{name} / Primitive / Recover"
    )
    if recovered != secret:
        raise RuntimeError(f"{name} primitive correctness failed")
    add(rec, samples, "primitive_compare", name, "native", "hybrid_32_bytes",
        "recover", "32-byte key material", len(secret), policy_count)


def run_core_buffer(native, rec, scheme, payload, policy, attrs, policy_count, n, warm, quiet):
    name = SCHEMES[scheme]
    samples, pair = measure(lambda: native.backend(scheme).setup(), n, warm, quiet, f"{name} / Buffer / Setup")
    add(rec, samples, "core", name, "buffer", "standard", "setup", "baseline", len(payload), policy_count)
    pk, msk = pair

    samples, sk = measure(lambda: native.backend(scheme).keygen(msk, attrs), n, warm, quiet, f"{name} / Buffer / KeyGen")
    add(rec, samples, "core", name, "buffer", "standard", "keygen", "baseline", len(payload), policy_count)

    samples, ct = measure(lambda: native.backend(scheme).encrypt(pk, payload, policy), n, warm, quiet, f"{name} / Buffer / Encrypt")
    add(rec, samples, "core", name, "buffer", "standard", "encrypt", "baseline", len(payload), policy_count, {"ciphertext_bytes": len(ct)})

    samples, pt = measure(lambda: native.api.decrypt(sk, ct), n, warm, quiet, f"{name} / Buffer / Decrypt")
    if pt != payload:
        raise RuntimeError(f"{name} buffer correctness failed")
    add(rec, samples, "core", name, "buffer", "standard", "decrypt", "baseline", len(payload), policy_count)


def run_core_file(native, rec, scheme, payload, policy, attrs, policy_count, n, warm, quiet, tmp):
    name = SCHEMES[scheme]
    d = tmp / f"file_{name.lower()}"
    d.mkdir(parents=True, exist_ok=True)
    pt, sk, ct, out = d / "input.bin", d / "user.key", d / "ct.bin", d / "out.bin"
    pt.write_bytes(payload)

    samples, _ = measure(lambda: native.api.setup_files(str(d) + os.sep, scheme=scheme), n, warm, quiet, f"{name} / File / Setup")
    add(rec, samples, "core", name, "file", "standard", "setup", "baseline", len(payload), policy_count)

    msk, pk = d / "cpabe_msk.key", d / "cpabe_pk.key"
    samples, _ = measure(lambda: native.api.generate_secret_key_file(msk, attrs, sk, scheme=scheme), n, warm, quiet, f"{name} / File / KeyGen")
    add(rec, samples, "core", name, "file", "standard", "keygen", "baseline", len(payload), policy_count)

    samples, _ = measure(lambda: native.api.encrypt_file(pk, pt, policy, ct, scheme=scheme), n, warm, quiet, f"{name} / File / Encrypt")
    add(rec, samples, "core", name, "file", "standard", "encrypt", "baseline", len(payload), policy_count, {"ciphertext_bytes": ct.stat().st_size})

    samples, _ = measure(lambda: native.api.decrypt_file(sk, ct, out), n, warm, quiet, f"{name} / File / Decrypt")
    if out.read_bytes() != payload:
        raise RuntimeError(f"{name} file correctness failed")
    add(rec, samples, "core", name, "file", "standard", "decrypt", "baseline", len(payload), policy_count)


def run_pqc_buffer(native, rec, scheme, payload, policy, attrs, policy_count, n, warm, quiet):
    name = SCHEMES[scheme]
    samples, setup = measure(lambda: native.backend(scheme).setup_with_signing(), n, warm, quiet, f"{name} / PQC / Setup")
    add(rec, samples, "pqc", name, "buffer", "pqc", "setup_pqc", "baseline", len(payload), policy_count)
    pk, msk, pq_pk, pq_sk = setup
    user_sk = native.backend(scheme).keygen(msk, attrs)

    samples, ct = measure(lambda: native.backend(scheme).encrypt_and_sign(pk, pq_sk, payload, policy), n, warm, quiet, f"{name} / PQC / Encrypt+Sign")
    add(rec, samples, "pqc", name, "buffer", "pqc", "encrypt_sign", "baseline", len(payload), policy_count, {"ciphertext_bytes": len(ct)})

    samples, pt = measure(lambda: native.api.decrypt_and_verify(user_sk, pq_pk, ct), n, warm, quiet, f"{name} / PQC / Decrypt+Verify")
    if pt != payload:
        raise RuntimeError(f"{name} PQC correctness failed")
    add(rec, samples, "pqc", name, "buffer", "pqc", "decrypt_verify", "baseline", len(payload), policy_count)


def run_mldsa(native, rec, sizes, base, warm, quiet):
    samples, pair = measure(native.signer.generate_keypair, base, warm, quiet, "ML-DSA-87 / KeyGen")
    pk, sk = pair
    add(rec, samples, "mldsa", "ML-DSA-87", "native", "primitive", "keygen", "keypair", 0, 0, {"pk_bytes": len(pk), "sk_bytes": len(sk)})
    for size in sizes:
        n = adaptive_iterations(base, size)
        msg = os.urandom(size)
        samples, sig = measure(lambda: native.signer.sign(msg, sk), n, warm, quiet, f"ML-DSA-87 / Sign / {human_bytes(size)}")
        add(rec, samples, "mldsa", "ML-DSA-87", "native", "primitive", "sign", human_bytes(size), size, 0, {"signature_bytes": len(sig)})
        if not native.signer.verify(msg, sig, pk):
            raise RuntimeError("ML-DSA signature correctness failed")
        samples, _ = measure(lambda: native.signer.verify(msg, sig, pk), n, warm, quiet, f"ML-DSA-87 / Verify / {human_bytes(size)}")
        add(rec, samples, "mldsa", "ML-DSA-87", "native", "primitive", "verify", human_bytes(size), size, 0)


def run_aes(native, rec, sizes, base, warm, quiet):
    key, aad = native.aes.generate_key(), os.urandom(64)
    for size in sizes:
        n = adaptive_iterations(base, size)
        pt = os.urandom(size)
        nonces = iter([native.aes.generate_nonce() for _ in range(n + warm)])
        def encrypt():
            iv = next(nonces)
            return iv, native.aes.encrypt(key, iv, pt, aad)
        samples, encrypted = measure(encrypt, n, warm, quiet, f"AES-256-GCM / Encrypt / {human_bytes(size)}")
        iv, ct = encrypted
        med = statistics.median(samples)
        thr = (size / 1048576) / (med / 1000) if med else 0
        add(rec, samples, "aes_gcm", "AES-256-GCM", "native", "primitive", "encrypt", human_bytes(size), size, 0, {"median_throughput_mib_s": thr})
        if native.aes.decrypt(key, iv, ct, aad) != pt:
            raise RuntimeError("AES-GCM correctness failed")
        samples, _ = measure(lambda: native.aes.decrypt(key, iv, ct, aad), n, warm, quiet, f"AES-256-GCM / Decrypt / {human_bytes(size)}")
        med = statistics.median(samples)
        thr = (size / 1048576) / (med / 1000) if med else 0
        add(rec, samples, "aes_gcm", "AES-256-GCM", "native", "primitive", "decrypt", human_bytes(size), size, 0, {"median_throughput_mib_s": thr})


def run_policy_scaling(native, rec, sizes, n, warm, quiet, covercrypt_dimensions):
    payload = os.urandom(4096)
    for scheme in NATIVE_SCHEMES:
        name = SCHEMES[scheme]
        pk, msk = native.backend(scheme).setup()
        for count in sizes:
            policy, attrs = (
                covercrypt_policy_attrs(count, covercrypt_dimensions)
                if scheme == COVERCRYPT
                else (policy_for(count), attrs_for(count))
            )
            sk = native.backend(scheme).keygen(msk, attrs)
            samples, ct = measure(lambda p=policy: native.backend(scheme).encrypt(pk, payload, p), n, warm, quiet, f"{name} / Policy {count} attrs / Encrypt")
            add(rec, samples, "policy_scaling", name, "buffer", "standard", "encrypt", f"{count} attrs", len(payload), count)
            samples, pt = measure(lambda c=ct: native.api.decrypt(sk, c), n, warm, quiet, f"{name} / Policy {count} attrs / Decrypt")
            if pt != payload:
                raise RuntimeError(f"{name} policy scaling failed at {count}")
            add(rec, samples, "policy_scaling", name, "buffer", "standard", "decrypt", f"{count} attrs", len(payload), count)


def run_payload_scaling(native, rec, sizes, base, warm, quiet, policy_count, with_pqc, covercrypt_dimensions):
    for scheme in NATIVE_SCHEMES:
        name = SCHEMES[scheme]
        policy, attrs = (
            covercrypt_policy_attrs(policy_count, covercrypt_dimensions)
            if scheme == COVERCRYPT
            else (policy_for(policy_count), attrs_for(policy_count))
        )
        pk, msk = native.backend(scheme).setup()
        sk = native.backend(scheme).keygen(msk, attrs)
        if with_pqc:
            ppk, pmsk, pq_pk, pq_sk = native.backend(scheme).setup_with_signing()
            puser = native.backend(scheme).keygen(pmsk, attrs)
        for size in sizes:
            n = adaptive_iterations(base, size)
            payload = os.urandom(size)
            samples, ct = measure(lambda d=payload: native.backend(scheme).encrypt(pk, d, policy), n, warm, quiet, f"{name} / Payload {human_bytes(size)} / Encrypt")
            add(rec, samples, "payload_scaling", name, "buffer", "standard", "encrypt", human_bytes(size), size, policy_count)
            samples, pt = measure(lambda c=ct: native.api.decrypt(sk, c), n, warm, quiet, f"{name} / Payload {human_bytes(size)} / Decrypt")
            if pt != payload:
                raise RuntimeError(f"{name} payload scaling failed")
            add(rec, samples, "payload_scaling", name, "buffer", "standard", "decrypt", human_bytes(size), size, policy_count)
            if with_pqc:
                samples, pct = measure(lambda d=payload: native.backend(scheme).encrypt_and_sign(ppk, pq_sk, d, policy), n, warm, quiet, f"{name} / Payload {human_bytes(size)} / Encrypt+Sign")
                add(rec, samples, "payload_scaling", name, "buffer", "pqc", "encrypt_sign", human_bytes(size), size, policy_count)
                samples, ppt = measure(lambda c=pct: native.api.decrypt_and_verify(puser, pq_pk, c), n, warm, quiet, f"{name} / Payload {human_bytes(size)} / Decrypt+Verify")
                if ppt != payload:
                    raise RuntimeError(f"{name} PQC payload scaling failed")
                add(rec, samples, "payload_scaling", name, "buffer", "pqc", "decrypt_verify", human_bytes(size), size, policy_count)


def load_charm():
    """Resolve optional reference dependencies without running cryptography."""
    from charm.toolbox.pairinggroup import PairingGroup, GT
    from charm.schemes.abenc.ac17 import AC17CPABE
    return PairingGroup, GT, AC17CPABE


def run_charm(rec, n, warm, policy, count):
    try:
        PairingGroup, GT, AC17CPABE = load_charm()
    except Exception as exc:
        print(f"Charm-Crypto unavailable, skipped: {exc}")
        return False
    group = PairingGroup("BN254")
    ac17 = AC17CPABE(group_obj=group, assump_size=2)
    attrs = attrs_for(count).split()

    samples, pair = measure(ac17.setup, n, warm, False, "Charm-Crypto AC17 / Primitive / Setup")
    add(rec, samples, "primitive_compare", "Charm-Crypto AC17", "python", "GT_reference",
        "setup", "GT element", 0, count)
    pk, msk = pair
    samples, sk = measure(
        lambda: ac17.keygen(pk, msk, attrs), n, warm, False,
        "Charm-Crypto AC17 / Primitive / KeyGen"
    )
    add(rec, samples, "primitive_compare", "Charm-Crypto AC17", "python", "GT_reference",
        "keygen", "GT element", 0, count)
    msg = group.random(GT)
    samples, ct = measure(
        lambda: ac17.encrypt(pk, msg, policy), n, warm, False,
        "Charm-Crypto AC17 / Primitive / Protect"
    )
    add(rec, samples, "primitive_compare", "Charm-Crypto AC17", "python", "GT_reference",
        "protect", "GT element", 0, count)
    samples, out = measure(
        lambda: ac17.decrypt(pk, ct, sk), n, warm, False,
        "Charm-Crypto AC17 / Primitive / Recover"
    )
    if out != msg:
        raise RuntimeError("Charm correctness failed")
    add(rec, samples, "primitive_compare", "Charm-Crypto AC17", "python", "GT_reference",
        "recover", "GT element", 0, count)
    return True
