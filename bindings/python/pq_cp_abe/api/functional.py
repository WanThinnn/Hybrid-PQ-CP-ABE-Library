"""Typed public API. Legacy call_* wrappers retain their behavior.

This layer adds no console output; native file operations may still emit logs.
"""
import ctypes
from os import PathLike, fspath

from .._native import abe_lib, c_ubyte_p, get_function
from ..utils.validation import data as _data, text as _str
from ..utils.errors import AbeError, PolicyMismatchError, SignatureInvalidError, check_status as _check
from ..models import Scheme, AuthorityKeys, AuthoritySigningKeys
from ..models import MlDsaParameterSet, MlKemParameterSet, KeyPair, KemEncapsulation
from ..models import KemMode

__all__ = [
    "Scheme", "AbeError", "PolicyMismatchError", "SignatureInvalidError",
    "AuthorityKeys", "AuthoritySigningKeys", "setup", "setup_with_signing",
    "generate_secret_key", "encrypt", "decrypt", "encrypt_and_sign",
    "decrypt_and_verify", "setup_files", "setup_files_with_signing",
    "generate_secret_key_file", "encrypt_file", "decrypt_file",
    "encrypt_and_sign_file", "decrypt_and_verify_file",
    "MlDsaParameterSet", "MlKemParameterSet", "KeyPair", "KemEncapsulation",
    "aes_gcm_generate_key", "aes_gcm_encrypt", "aes_gcm_decrypt",
    "ml_dsa_generate_keypair", "ml_dsa_sign", "ml_dsa_verify",
    "ml_kem_generate_keypair", "ml_kem_encapsulate", "ml_kem_decapsulate",
    "KemMode", "covercrypt_setup", "covercrypt_ml_kem_parameter_set",
    "covercrypt_add_dimension_with_mode", "ml_dsa_get_sizes", "ml_kem_get_sizes",
]


def _outputs(name, *arguments, count=1, scheme=None, parameters=()):
    outputs = [(c_ubyte_p(), ctypes.c_size_t()) for _ in range(count)]
    args = list(arguments)
    for pointer, size in outputs:
        args.extend((ctypes.byref(pointer), ctypes.byref(size)))
    if scheme is not None:
        args.append(int(Scheme(scheme)))
    try:
        _check(get_function(name)(*args, *parameters), name)
        values = tuple(ctypes.string_at(pointer, size.value) if size.value else b""
                       for pointer, size in outputs)
        return values[0] if count == 1 else values
    finally:
        for pointer, _ in outputs:
            if pointer:
                abe_lib.freeBuffer(pointer)


def _buffer(value: bytes):
    return _data(value), len(value)


def _path(value: str | PathLike[str]) -> bytes:
    return _str(fspath(value))


def setup(*, scheme: Scheme = Scheme.COVERCRYPT) -> AuthorityKeys:
    """Create an authority in memory, using the native scheme configuration."""
    return AuthorityKeys(*_outputs("hybrid_cpabe_setupBuffer_with_scheme", count=2, scheme=scheme))


def covercrypt_setup(config_json: str, *, mode: KemMode = KemMode.HYBRIDIZED) -> AuthorityKeys:
    """Explicit configuration; does not read or modify the process environment."""
    return AuthorityKeys(*_outputs("hybrid_cpabe_covercrypt_setupBuffer_from_json",
                                   _str(config_json), int(KemMode(mode)), count=2))


def covercrypt_ml_kem_parameter_set() -> MlKemParameterSet:
    return MlKemParameterSet(get_function("hybrid_cpabe_covercrypt_ml_kem_parameter_set")())


def covercrypt_add_dimension_with_mode(master_secret_key: bytes, dimension_json: str, *,
                                       mode: KemMode = KemMode.HYBRIDIZED) -> AuthorityKeys:
    return AuthorityKeys(*_outputs("hybrid_cpabe_covercrypt_add_dimensionBuffer_with_mode",
                                   *_buffer(master_secret_key), _str(dimension_json), int(KemMode(mode)), count=2))


def _sizes(name, parameter, count):
    lengths = [ctypes.c_size_t() for _ in range(count)]
    _check(get_function(name)(int(parameter), *(ctypes.byref(length) for length in lengths)), name)
    return tuple(length.value for length in lengths)


def ml_dsa_get_sizes(parameter_set: MlDsaParameterSet = MlDsaParameterSet.ML_DSA_87) -> tuple[int, int, int]:
    """Return public key, secret key and signature sizes in bytes."""
    return _sizes("ml_dsa_get_sizes", MlDsaParameterSet(parameter_set), 3)


def ml_kem_get_sizes(parameter_set: MlKemParameterSet = MlKemParameterSet.ML_KEM_768) -> tuple[int, int, int, int]:
    """Return public key, secret key, ciphertext and shared secret sizes in bytes."""
    return _sizes("ml_kem_get_sizes", MlKemParameterSet(parameter_set), 4)


def setup_with_signing(*, scheme: Scheme = Scheme.COVERCRYPT,
                       ml_dsa_parameter_set: MlDsaParameterSet | None = None) -> AuthoritySigningKeys:
    """Create an authority and ML-DSA signing keys for encrypt_and_sign."""
    if ml_dsa_parameter_set is None:
        return AuthoritySigningKeys(*_outputs("hybrid_cpabe_setupBuffer_with_pqc_scheme", count=4, scheme=scheme))
    return AuthoritySigningKeys(*_outputs("hybrid_cpabe_setupBuffer_with_ml_dsa", count=4, scheme=scheme,
                                         parameters=(MlDsaParameterSet(ml_dsa_parameter_set),)))


def _aes_bits(value):
    if value not in (128, 192, 256):
        raise ValueError("AES key size must be 128, 192 or 256 bits")
    return value


def generate_secret_key(master_secret_key: bytes, attributes: str, *,
                        scheme: Scheme = Scheme.COVERCRYPT) -> bytes:
    return _outputs("hybrid_cpabe_genkeyBuffer_with_scheme",
                    *_buffer(master_secret_key), _str(attributes), scheme=scheme)


def encrypt(public_key: bytes, plaintext: bytes, policy: str, *,
            scheme: Scheme = Scheme.COVERCRYPT, aes_key_bits: int | None = None) -> bytes:
    arguments = (*_buffer(public_key), *_buffer(plaintext), _str(policy))
    if aes_key_bits is None:
        return _outputs("hybrid_cpabe_encryptBuffer_with_scheme", *arguments, scheme=scheme)
    return _outputs("hybrid_cpabe_encryptBuffer_with_params", *arguments, scheme=scheme,
                    parameters=(_aes_bits(aes_key_bits),))


def decrypt(secret_key: bytes, ciphertext: bytes) -> bytes:
    """Decrypt; the native implementation detects the ciphertext scheme."""
    return _outputs("hybrid_cpabe_decryptBuffer", *_buffer(secret_key), *_buffer(ciphertext))


def encrypt_and_sign(public_key: bytes, signing_key: bytes, plaintext: bytes,
                     policy: str, *, scheme: Scheme = Scheme.COVERCRYPT,
                     aes_key_bits: int | None = None,
                     ml_dsa_parameter_set: MlDsaParameterSet | None = None) -> bytes:
    arguments = (*_buffer(public_key), *_buffer(signing_key), *_buffer(plaintext), _str(policy))
    if aes_key_bits is None and ml_dsa_parameter_set is None:
        return _outputs("hybrid_cpabe_encryptBuffer_and_sign_with_scheme", *arguments, scheme=scheme)
    return _outputs("hybrid_cpabe_encryptBuffer_and_sign_with_params", *arguments, scheme=scheme,
                    parameters=(_aes_bits(256 if aes_key_bits is None else aes_key_bits),
                                MlDsaParameterSet(87 if ml_dsa_parameter_set is None else ml_dsa_parameter_set)))


def decrypt_and_verify(secret_key: bytes, verification_key: bytes, ciphertext: bytes) -> bytes:
    return _outputs("hybrid_cpabe_decryptBuffer_and_verify", *_buffer(secret_key),
                    *_buffer(verification_key), *_buffer(ciphertext))


def setup_files(output_path: str | PathLike[str], *, scheme: Scheme = Scheme.COVERCRYPT) -> None:
    """Use native setup's path/prefix naming for the generated key files."""
    _check(abe_lib.setup_with_scheme(_path(output_path), int(Scheme(scheme))), "setup_files")


def setup_files_with_signing(output_path: str | PathLike[str], *,
                             scheme: Scheme = Scheme.COVERCRYPT,
                             ml_dsa_parameter_set: MlDsaParameterSet | None = None,
                             legacy_key_names: bool = True) -> None:
    arguments = (_path(output_path), int(Scheme(scheme)))
    if legacy_key_names and ml_dsa_parameter_set is None:
        _check(abe_lib.hybrid_cpabe_setup_with_pqc_scheme(*arguments), "setup_files_with_signing")
        return
    native = "hybrid_cpabe_setup_with_ml_dsa" if legacy_key_names else "hybrid_cpabe_setup_with_signing_keys"
    parameter = MlDsaParameterSet(87 if ml_dsa_parameter_set is None else ml_dsa_parameter_set)
    _check(get_function(native)(*arguments, parameter), "setup_files_with_signing")


def generate_secret_key_file(master_secret_key_path: str | PathLike[str], attributes: str,
                             output_path: str | PathLike[str], *,
                             scheme: Scheme = Scheme.COVERCRYPT) -> None:
    _check(abe_lib.generateSecretKey_with_scheme(_path(master_secret_key_path), _str(attributes),
            _path(output_path), int(Scheme(scheme))), "generate_secret_key_file")


def encrypt_file(public_key_path: str | PathLike[str], plaintext_path: str | PathLike[str],
                 policy: str, output_path: str | PathLike[str], *,
                 scheme: Scheme = Scheme.COVERCRYPT, aes_key_bits: int | None = None) -> None:
    arguments = (_path(public_key_path), _path(plaintext_path), _str(policy), _path(output_path), int(Scheme(scheme)))
    if aes_key_bits is None:
        _check(abe_lib.hybrid_cpabe_encrypt_with_scheme(*arguments), "encrypt_file")
    else:
        _check(get_function("hybrid_cpabe_encrypt_with_params")(*arguments, _aes_bits(aes_key_bits)), "encrypt_file")


def decrypt_file(secret_key_path: str | PathLike[str], ciphertext_path: str | PathLike[str],
                 output_path: str | PathLike[str]) -> None:
    _check(abe_lib.hybrid_cpabe_decrypt(_path(secret_key_path), _path(ciphertext_path),
            _path(output_path)), "decrypt_file")


def encrypt_and_sign_file(public_key_path: str | PathLike[str], signing_key_path: str | PathLike[str],
                          plaintext_path: str | PathLike[str], policy: str,
                          output_path: str | PathLike[str], *,
                          scheme: Scheme = Scheme.COVERCRYPT, aes_key_bits: int | None = None,
                          ml_dsa_parameter_set: MlDsaParameterSet | None = None) -> None:
    arguments = (_path(public_key_path), _path(signing_key_path), _path(plaintext_path), _str(policy),
                 _path(output_path), int(Scheme(scheme)))
    if aes_key_bits is None and ml_dsa_parameter_set is None:
        _check(abe_lib.hybrid_cpabe_encrypt_and_sign_with_scheme(*arguments), "encrypt_and_sign_file")
    else:
        _check(get_function("hybrid_cpabe_encrypt_and_sign_with_params")(
            *arguments, _aes_bits(256 if aes_key_bits is None else aes_key_bits),
            MlDsaParameterSet(87 if ml_dsa_parameter_set is None else ml_dsa_parameter_set)), "encrypt_and_sign_file")


def decrypt_and_verify_file(secret_key_path: str | PathLike[str], verification_key_path: str | PathLike[str],
                            ciphertext_path: str | PathLike[str], output_path: str | PathLike[str]) -> None:
    _check(abe_lib.hybrid_cpabe_decrypt_and_verify(_path(secret_key_path), _path(verification_key_path),
            _path(ciphertext_path), _path(output_path)), "decrypt_and_verify_file")


def aes_gcm_generate_key(key_size_bits: int = 256) -> bytes:
    _aes_bits(key_size_bits)
    if not hasattr(abe_lib, "aes_gcm_generate_key"):
        from secrets import token_bytes
        return token_bytes(key_size_bits // 8)
    return _outputs("aes_gcm_generate_key", key_size_bits)


def aes_gcm_encrypt(key: bytes, iv: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    if len(key) not in (16, 24, 32) or len(iv) < 12:
        raise ValueError("Use a 16/24/32-byte AES key and a nonce of at least 12 bytes")
    return _outputs("aes_gcm_encrypt", *_buffer(key), *_buffer(iv), *_buffer(plaintext), *_buffer(aad))


def aes_gcm_decrypt(key: bytes, iv: bytes, ciphertext: bytes, aad: bytes = b"") -> bytes:
    if len(key) not in (16, 24, 32) or len(iv) < 12:
        raise ValueError("Use a 16/24/32-byte AES key and a nonce of at least 12 bytes")
    return _outputs("aes_gcm_decrypt", *_buffer(key), *_buffer(iv), *_buffer(ciphertext), *_buffer(aad))


def ml_dsa_generate_keypair(*, parameter_set: MlDsaParameterSet = MlDsaParameterSet.ML_DSA_87) -> KeyPair:
    if MlDsaParameterSet(parameter_set) == MlDsaParameterSet.ML_DSA_87 and not hasattr(abe_lib, "ml_dsa_generate_keypair"):
        return KeyPair(*_outputs("ml_dsa_87_generate_keypair", count=2))
    return KeyPair(*_outputs("ml_dsa_generate_keypair", int(MlDsaParameterSet(parameter_set)), count=2))


def ml_dsa_sign(message: bytes, secret_key: bytes, *,
                parameter_set: MlDsaParameterSet = MlDsaParameterSet.ML_DSA_87) -> bytes:
    if MlDsaParameterSet(parameter_set) == MlDsaParameterSet.ML_DSA_87 and not hasattr(abe_lib, "ml_dsa_sign"):
        key = _data(secret_key)
        if len(secret_key) != 4896:
            raise ValueError("ML-DSA-87 secret key must be 4896 bytes")
        return _outputs("ml_dsa_87_sign", *_buffer(message), key)
    return _outputs("ml_dsa_sign", int(MlDsaParameterSet(parameter_set)), *_buffer(message), *_buffer(secret_key))


def ml_dsa_verify(message: bytes, signature: bytes, public_key: bytes, *,
                  parameter_set: MlDsaParameterSet = MlDsaParameterSet.ML_DSA_87) -> bool:
    if MlDsaParameterSet(parameter_set) == MlDsaParameterSet.ML_DSA_87 and not hasattr(abe_lib, "ml_dsa_verify"):
        key = _data(public_key)
        if len(public_key) != 2592:
            raise ValueError("ML-DSA-87 public key must be 2592 bytes")
        code = get_function("ml_dsa_87_verify")(*_buffer(message), *_buffer(signature), key)
    else:
        code = get_function("ml_dsa_verify")(int(MlDsaParameterSet(parameter_set)),
                *_buffer(message), *_buffer(signature), *_buffer(public_key))
    if code == -9:
        return False
    _check(code, "ml_dsa_verify")
    return True


def ml_kem_generate_keypair(*, parameter_set: MlKemParameterSet = MlKemParameterSet.ML_KEM_768) -> KeyPair:
    return KeyPair(*_outputs("ml_kem_generate_keypair", int(MlKemParameterSet(parameter_set)), count=2))


def ml_kem_encapsulate(public_key: bytes, *,
                       parameter_set: MlKemParameterSet = MlKemParameterSet.ML_KEM_768) -> KemEncapsulation:
    return KemEncapsulation(*_outputs("ml_kem_encapsulate", int(MlKemParameterSet(parameter_set)),
                                     *_buffer(public_key), count=2))


def ml_kem_decapsulate(secret_key: bytes, ciphertext: bytes, *,
                       parameter_set: MlKemParameterSet = MlKemParameterSet.ML_KEM_768) -> bytes:
    """Recover a secret; implicit rejection does not authenticate the ciphertext."""
    return _outputs("ml_kem_decapsulate", int(MlKemParameterSet(parameter_set)),
                    *_buffer(secret_key), *_buffer(ciphertext))
