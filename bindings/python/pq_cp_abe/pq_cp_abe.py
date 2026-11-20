"""Convenient facade over the selected CP-ABE implementation."""
from .abe import BaseCPABE, AC17CPABE, TKN20CPABE, CoverCryptABE
from .models import AuthorityKeys, AuthoritySigningKeys, Scheme, KemMode, MlKemParameterSet


class PqCpAbe(BaseCPABE):
    def __init__(self, *, scheme: Scheme = Scheme.COVERCRYPT, config=None,
                 mode: KemMode = KemMode.HYBRIDIZED,
                 parameter_set: MlKemParameterSet = MlKemParameterSet.ML_KEM_768):
        selected = Scheme(scheme)
        if selected == Scheme.COVERCRYPT:
            backend = CoverCryptABE(config=config, mode=mode, parameter_set=parameter_set)
        else:
            if config is not None or mode != KemMode.HYBRIDIZED or parameter_set != MlKemParameterSet.ML_KEM_768:
                raise ValueError("config, mode and parameter_set apply only to CoverCrypt")
            backend = AC17CPABE() if selected == Scheme.AC17 else TKN20CPABE()
        self._backend = backend

    @property
    def backend(self) -> BaseCPABE:
        return self._backend

    @property
    def scheme(self) -> Scheme:
        return self.backend.scheme

    def setup(self) -> AuthorityKeys:
        return self.backend.setup()

    def setup_with_signing(self) -> AuthoritySigningKeys:
        return self.backend.setup_with_signing()

    def keygen(self, master_secret_key: bytes, attributes: str) -> bytes:
        return self.backend.keygen(master_secret_key, attributes)

    def encrypt(self, public_key: bytes, plaintext: bytes, policy: str) -> bytes:
        return self.backend.encrypt(public_key, plaintext, policy)

    def decrypt(self, secret_key: bytes, ciphertext: bytes) -> bytes:
        return self.backend.decrypt(secret_key, ciphertext)
