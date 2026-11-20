"""Common CP-ABE contract. Scheme objects own configuration, not keys."""
from abc import ABC, abstractmethod
from ..api import functional as api
from ..models import AuthorityKeys, AuthoritySigningKeys, Scheme


class BaseCPABE(ABC):
    @property
    @abstractmethod
    def scheme(self) -> Scheme:
        """The immutable scheme selected for this object."""

    @abstractmethod
    def setup(self) -> AuthorityKeys:
        """Create an authority's public and master secret keys."""

    @abstractmethod
    def keygen(self, master_secret_key: bytes, attributes: str) -> bytes:
        """Issue a user secret key (stateless, like the functional buffer API)."""

    @abstractmethod
    def encrypt(self, public_key: bytes, plaintext: bytes, policy: str) -> bytes:
        """Encrypt arbitrary bytes under a policy."""

    @abstractmethod
    def decrypt(self, secret_key: bytes, ciphertext: bytes) -> bytes:
        """Decrypt bytes; ciphertexts carry their native scheme identifier."""

    def generate_secret_key(self, master_secret_key: bytes, attributes: str) -> bytes:
        return self.keygen(master_secret_key, attributes)

    def setup_with_signing(self) -> AuthoritySigningKeys:
        return api.setup_with_signing(scheme=self.scheme)

    def encrypt_and_sign(self, public_key: bytes, signing_key: bytes, plaintext: bytes, policy: str) -> bytes:
        return api.encrypt_and_sign(public_key, signing_key, plaintext, policy, scheme=self.scheme)

    def decrypt_and_verify(self, secret_key: bytes, verification_key: bytes, ciphertext: bytes) -> bytes:
        return api.decrypt_and_verify(secret_key, verification_key, ciphertext)


class _FunctionalCPABE(BaseCPABE):
    """Shared implementation used by the concrete native scheme adapters."""
    _scheme: Scheme

    @property
    def scheme(self) -> Scheme:
        return self._scheme

    def setup(self) -> AuthorityKeys:
        return api.setup(scheme=self.scheme)

    def keygen(self, master_secret_key: bytes, attributes: str) -> bytes:
        return api.generate_secret_key(master_secret_key, attributes, scheme=self.scheme)

    def encrypt(self, public_key: bytes, plaintext: bytes, policy: str) -> bytes:
        return api.encrypt(public_key, plaintext, policy, scheme=self.scheme)

    def decrypt(self, secret_key: bytes, ciphertext: bytes) -> bytes:
        return api.decrypt(secret_key, ciphertext)
