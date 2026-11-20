from dataclasses import dataclass
from ..api import functional as api
from ..models import KeyPair, MlDsaParameterSet


@dataclass(frozen=True)
class MlDsa:
    """Standalone ML-DSA using raw keys, not combined-API Base64 keys."""
    parameter_set: MlDsaParameterSet = MlDsaParameterSet.ML_DSA_87

    def __post_init__(self):
        object.__setattr__(self, "parameter_set", MlDsaParameterSet(self.parameter_set))

    def generate_keypair(self) -> KeyPair:
        return api.ml_dsa_generate_keypair(parameter_set=self.parameter_set)

    def sign(self, message: bytes, secret_key: bytes) -> bytes:
        return api.ml_dsa_sign(message, secret_key, parameter_set=self.parameter_set)

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        return api.ml_dsa_verify(message, signature, public_key, parameter_set=self.parameter_set)
