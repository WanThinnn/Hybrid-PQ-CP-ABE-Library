from dataclasses import dataclass
from ..api import functional as api
from ..models import KeyPair, KemEncapsulation, MlKemParameterSet


@dataclass(frozen=True)
class MlKem:
    """Standalone KEM. Decapsulation alone does not authenticate ciphertexts."""
    parameter_set: MlKemParameterSet = MlKemParameterSet.ML_KEM_768

    def __post_init__(self):
        object.__setattr__(self, "parameter_set", MlKemParameterSet(self.parameter_set))

    def generate_keypair(self) -> KeyPair:
        return api.ml_kem_generate_keypair(parameter_set=self.parameter_set)

    def get_sizes(self) -> tuple[int, int, int, int]:
        return api.ml_kem_get_sizes(self.parameter_set)

    def encapsulate(self, public_key: bytes) -> KemEncapsulation:
        return api.ml_kem_encapsulate(public_key, parameter_set=self.parameter_set)

    def decapsulate(self, secret_key: bytes, ciphertext: bytes) -> bytes:
        return api.ml_kem_decapsulate(secret_key, ciphertext, parameter_set=self.parameter_set)
