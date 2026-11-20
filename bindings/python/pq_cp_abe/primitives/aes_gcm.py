from dataclasses import dataclass
from secrets import token_bytes
from ..api import functional as api


@dataclass(frozen=True)
class AesGcm:
    """AES-GCM with a fixed key size. Supply a unique nonce for each encryption."""
    key_size_bits: int = 256

    def __post_init__(self):
        if not isinstance(self.key_size_bits, int) or self.key_size_bits not in (128, 192, 256):
            raise ValueError("AES key size must be 128, 192 or 256 bits")

    def generate_key(self) -> bytes:
        return api.aes_gcm_generate_key(self.key_size_bits)

    def generate_nonce(self) -> bytes:
        return token_bytes(12)

    def _check_key(self, key: bytes) -> None:
        if not isinstance(key, bytes):
            raise TypeError("Expected bytes for native input")
        if len(key) * 8 != self.key_size_bits:
            raise ValueError(f"This object requires a {self.key_size_bits}-bit key")

    def encrypt(self, key: bytes, nonce: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
        self._check_key(key)
        return api.aes_gcm_encrypt(key, nonce, plaintext, aad)

    def decrypt(self, key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes = b"") -> bytes:
        self._check_key(key)
        return api.aes_gcm_decrypt(key, nonce, ciphertext, aad)
