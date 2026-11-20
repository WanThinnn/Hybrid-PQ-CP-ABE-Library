"""Hybrid-PQ-CP-ABE Python bindings."""
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

_project_dir = Path(__file__).resolve().parent.parent
_root_version = _project_dir.parents[1] / "VERSION"
if (_project_dir / "pyproject.toml").is_file() and _root_version.is_file():
    # Ignore stale egg-info or another installed copy when importing from source.
    __version__ = _root_version.read_text(encoding="utf-8").strip()
else:
    try:
        __version__ = version("pq-cp-abe")
    except PackageNotFoundError as exc:
        raise RuntimeError("Cannot resolve pq-cp-abe version: no installed metadata or root VERSION") from exc

from ._native import abe_lib as native  # Complete low-level C ABI (33 exported DLL symbols)

from .extended_api import (
    setup_buffer,
    setup_buffer_with_pqc,
    genkey_buffer,
    covercrypt_add_attribute,
    covercrypt_add_dimension,
    covercrypt_add_attribute_buffer,
    covercrypt_add_dimension_buffer,
    ml_dsa_87_generate_keypair,
    ml_dsa_87_sign,
    ml_dsa_87_verify,
    aes_gcm_encrypt,
    aes_gcm_decrypt,
    get_version,
    get_error_message,
)

from .api import (
    CPABE_SCHEME_AC17,
    CPABE_SCHEME_TKN20,
    CPABE_SCHEME_COVERCRYPT,
    HCPABE_SUCCESS,
    HCPABE_ERR_FILE_NOT_FOUND,
    HCPABE_ERR_INVALID_KEY,
    HCPABE_ERR_POLICY_MISMATCH,
    HCPABE_ERR_CRYPTO_FAILED,
    HCPABE_ERR_INVALID_PARAM,
    HCPABE_ERR_MEMORY,
    HCPABE_ERR_UNSUPPORTED_FORMAT,
    HCPABE_ERR_VERSION_MISMATCH,
    HCPABE_ERR_SIGNATURE_INVALID,
    call_setup,
    call_generate_secret_key,
    call_hybrid_cpabe_encrypt,
    call_hybrid_cpabe_decrypt,
    call_hybrid_cpabe_encryptBuffer,
    call_hybrid_cpabe_decryptBuffer,
    call_hybrid_cpabe_setup_with_pqc,
    call_hybrid_cpabe_encrypt_and_sign,
    call_hybrid_cpabe_decrypt_and_verify,
    call_hybrid_cpabe_encryptBuffer_and_sign,
    call_hybrid_cpabe_decryptBuffer_and_verify,
    call_setup_with_scheme,
    call_hybrid_cpabe_setup_with_pqc_scheme,
    call_generate_secret_key_with_scheme,
    call_hybrid_cpabe_encrypt_with_scheme,
    call_hybrid_cpabe_encryptBuffer_with_scheme,
    call_hybrid_cpabe_encrypt_and_sign_with_scheme,
    call_hybrid_cpabe_encryptBuffer_and_sign_with_scheme,
)

__all__ = [
    "native",
    "setup_buffer",
    "setup_buffer_with_pqc",
    "genkey_buffer",
    "covercrypt_add_attribute",
    "covercrypt_add_dimension",
    "covercrypt_add_attribute_buffer",
    "covercrypt_add_dimension_buffer",
    "ml_dsa_87_generate_keypair",
    "ml_dsa_87_sign",
    "ml_dsa_87_verify",
    "aes_gcm_encrypt",
    "aes_gcm_decrypt",
    "get_version",
    "get_error_message",
    "CPABE_SCHEME_AC17",
    "CPABE_SCHEME_TKN20",
    "CPABE_SCHEME_COVERCRYPT",
    "HCPABE_SUCCESS",
    "HCPABE_ERR_FILE_NOT_FOUND",
    "HCPABE_ERR_INVALID_KEY",
    "HCPABE_ERR_POLICY_MISMATCH",
    "HCPABE_ERR_CRYPTO_FAILED",
    "HCPABE_ERR_INVALID_PARAM",
    "HCPABE_ERR_MEMORY",
    "HCPABE_ERR_UNSUPPORTED_FORMAT",
    "HCPABE_ERR_VERSION_MISMATCH",
    "HCPABE_ERR_SIGNATURE_INVALID",
    "call_setup",
    "call_generate_secret_key",
    "call_hybrid_cpabe_encrypt",
    "call_hybrid_cpabe_decrypt",
    "call_hybrid_cpabe_encryptBuffer",
    "call_hybrid_cpabe_decryptBuffer",
    "call_hybrid_cpabe_setup_with_pqc",
    "call_hybrid_cpabe_encrypt_and_sign",
    "call_hybrid_cpabe_decrypt_and_verify",
    "call_hybrid_cpabe_encryptBuffer_and_sign",
    "call_hybrid_cpabe_decryptBuffer_and_verify",
    "call_setup_with_scheme",
    "call_hybrid_cpabe_setup_with_pqc_scheme",
    "call_generate_secret_key_with_scheme",
    "call_hybrid_cpabe_encrypt_with_scheme",
    "call_hybrid_cpabe_encryptBuffer_with_scheme",
    "call_hybrid_cpabe_encrypt_and_sign_with_scheme",
    "call_hybrid_cpabe_encryptBuffer_and_sign_with_scheme",
]

# Additive public API: existing names and legacy return/error behavior stay intact.
from . import modern_api as _modern_api
from .modern_api import *

__all__ += _modern_api.__all__
