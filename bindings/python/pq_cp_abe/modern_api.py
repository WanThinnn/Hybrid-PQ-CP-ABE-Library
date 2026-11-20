"""Typed public API. Legacy call_* wrappers retain their behavior.

This layer adds no console output; native file operations may still emit logs.
"""
import ctypes
from enum import IntEnum
from os import PathLike, fspath
from typing import NamedTuple

from ._native import abe_lib, c_ubyte_p
from .extended_api import _data, _str

__all__ = [
    "Scheme", "AbeError", "PolicyMismatchError", "SignatureInvalidError",
    "AuthorityKeys", "AuthoritySigningKeys", "setup", "setup_with_signing",
    "generate_secret_key", "encrypt", "decrypt", "encrypt_and_sign",
    "decrypt_and_verify", "setup_files", "setup_files_with_signing",
    "generate_secret_key_file", "encrypt_file", "decrypt_file",
    "encrypt_and_sign_file", "decrypt_and_verify_file",
]


class Scheme(IntEnum):
    AC17 = 0
    TKN20 = 1
    COVERCRYPT = 2


class AbeError(RuntimeError):
    """Native operation failure; code preserves the C ABI error number."""

    def __init__(self, code: int, operation: str):
        self.code = code
        self.operation = operation
        message = abe_lib.getErrorMessage(code)
        detail = message.decode("utf-8", errors="replace") if message else "Native operation failed"
        super().__init__(f"{operation}: {detail} (code: {code})")


class PolicyMismatchError(AbeError):
    """The user's attributes do not satisfy the ciphertext policy."""


class SignatureInvalidError(AbeError):
    """Signature verification failed."""


class AuthorityKeys(NamedTuple):
    public_key: bytes
    master_secret_key: bytes


class AuthoritySigningKeys(NamedTuple):
    """Signing keys use the native setup format (Base64-encoded bytes)."""

    public_key: bytes
    master_secret_key: bytes
    verification_key: bytes
    signing_key: bytes


def _check(code: int, operation: str) -> None:
    if code:
        error = {-3: PolicyMismatchError, -9: SignatureInvalidError}.get(code, AbeError)
        raise error(code, operation)


def _outputs(name, *arguments, count=1, scheme=None):
    outputs = [(c_ubyte_p(), ctypes.c_size_t()) for _ in range(count)]
    args = list(arguments)
    for pointer, size in outputs:
        args.extend((ctypes.byref(pointer), ctypes.byref(size)))
    if scheme is not None:
        args.append(int(Scheme(scheme)))
    try:
        _check(getattr(abe_lib, name)(*args), name)
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


def setup_with_signing(*, scheme: Scheme = Scheme.COVERCRYPT) -> AuthoritySigningKeys:
    """Create an authority and ML-DSA signing keys for encrypt_and_sign."""
    return AuthoritySigningKeys(*_outputs("hybrid_cpabe_setupBuffer_with_pqc_scheme", count=4, scheme=scheme))


def generate_secret_key(master_secret_key: bytes, attributes: str, *,
                        scheme: Scheme = Scheme.COVERCRYPT) -> bytes:
    return _outputs("hybrid_cpabe_genkeyBuffer_with_scheme",
                    *_buffer(master_secret_key), _str(attributes), scheme=scheme)


def encrypt(public_key: bytes, plaintext: bytes, policy: str, *,
            scheme: Scheme = Scheme.COVERCRYPT) -> bytes:
    return _outputs("hybrid_cpabe_encryptBuffer_with_scheme",
                    *_buffer(public_key), *_buffer(plaintext), _str(policy), scheme=scheme)


def decrypt(secret_key: bytes, ciphertext: bytes) -> bytes:
    """Decrypt; the native implementation detects the ciphertext scheme."""
    return _outputs("hybrid_cpabe_decryptBuffer", *_buffer(secret_key), *_buffer(ciphertext))


def encrypt_and_sign(public_key: bytes, signing_key: bytes, plaintext: bytes,
                     policy: str, *, scheme: Scheme = Scheme.COVERCRYPT) -> bytes:
    return _outputs("hybrid_cpabe_encryptBuffer_and_sign_with_scheme",
                    *_buffer(public_key), *_buffer(signing_key), *_buffer(plaintext),
                    _str(policy), scheme=scheme)


def decrypt_and_verify(secret_key: bytes, verification_key: bytes, ciphertext: bytes) -> bytes:
    return _outputs("hybrid_cpabe_decryptBuffer_and_verify", *_buffer(secret_key),
                    *_buffer(verification_key), *_buffer(ciphertext))


def setup_files(output_path: str | PathLike[str], *, scheme: Scheme = Scheme.COVERCRYPT) -> None:
    """Use native setup's path/prefix naming for the generated key files."""
    _check(abe_lib.setup_with_scheme(_path(output_path), int(Scheme(scheme))), "setup_files")


def setup_files_with_signing(output_path: str | PathLike[str], *,
                             scheme: Scheme = Scheme.COVERCRYPT) -> None:
    _check(abe_lib.hybrid_cpabe_setup_with_pqc_scheme(_path(output_path), int(Scheme(scheme))),
           "setup_files_with_signing")


def generate_secret_key_file(master_secret_key_path: str | PathLike[str], attributes: str,
                             output_path: str | PathLike[str], *,
                             scheme: Scheme = Scheme.COVERCRYPT) -> None:
    _check(abe_lib.generateSecretKey_with_scheme(_path(master_secret_key_path), _str(attributes),
            _path(output_path), int(Scheme(scheme))), "generate_secret_key_file")


def encrypt_file(public_key_path: str | PathLike[str], plaintext_path: str | PathLike[str],
                 policy: str, output_path: str | PathLike[str], *,
                 scheme: Scheme = Scheme.COVERCRYPT) -> None:
    _check(abe_lib.hybrid_cpabe_encrypt_with_scheme(_path(public_key_path), _path(plaintext_path),
            _str(policy), _path(output_path), int(Scheme(scheme))), "encrypt_file")


def decrypt_file(secret_key_path: str | PathLike[str], ciphertext_path: str | PathLike[str],
                 output_path: str | PathLike[str]) -> None:
    _check(abe_lib.hybrid_cpabe_decrypt(_path(secret_key_path), _path(ciphertext_path),
            _path(output_path)), "decrypt_file")


def encrypt_and_sign_file(public_key_path: str | PathLike[str], signing_key_path: str | PathLike[str],
                          plaintext_path: str | PathLike[str], policy: str,
                          output_path: str | PathLike[str], *,
                          scheme: Scheme = Scheme.COVERCRYPT) -> None:
    _check(abe_lib.hybrid_cpabe_encrypt_and_sign_with_scheme(_path(public_key_path),
            _path(signing_key_path), _path(plaintext_path), _str(policy), _path(output_path),
            int(Scheme(scheme))), "encrypt_and_sign_file")


def decrypt_and_verify_file(secret_key_path: str | PathLike[str], verification_key_path: str | PathLike[str],
                            ciphertext_path: str | PathLike[str], output_path: str | PathLike[str]) -> None:
    _check(abe_lib.hybrid_cpabe_decrypt_and_verify(_path(secret_key_path), _path(verification_key_path),
            _path(ciphertext_path), _path(output_path)), "decrypt_and_verify_file")
