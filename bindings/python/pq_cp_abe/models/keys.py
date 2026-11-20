"""Named results shared by functional and object APIs."""
from typing import NamedTuple

class AuthorityKeys(NamedTuple):
    public_key: bytes
    master_secret_key: bytes


class AuthoritySigningKeys(NamedTuple):
    """Signing keys use the native setup format (Base64-encoded bytes)."""

    public_key: bytes
    master_secret_key: bytes
    verification_key: bytes
    signing_key: bytes


class KeyPair(NamedTuple):
    public_key: bytes
    secret_key: bytes


class KemEncapsulation(NamedTuple):
    ciphertext: bytes
    shared_secret: bytes

