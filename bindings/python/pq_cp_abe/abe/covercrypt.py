import base64
import json
import os
from pathlib import Path
from collections.abc import Mapping
from .base import _FunctionalCPABE
from ..api import functional as api, legacy
from ..models import AuthorityKeys, AuthoritySigningKeys, KemMode, MlDsaParameterSet, MlKemParameterSet, Scheme


class CoverCryptABE(_FunctionalCPABE):
    """CoverCrypt using an instance-local configuration snapshot.

    This build uses ML-KEM-768. Standalone MlKem supports other parameter sets
    independently. Vendor code and serialized CoverCrypt keys are unchanged.
    """
    _scheme = Scheme.COVERCRYPT

    def __init__(self, *, config: Mapping | str | None = None,
                 mode: KemMode = KemMode.HYBRIDIZED,
                 parameter_set: MlKemParameterSet = MlKemParameterSet.ML_KEM_768):
        parameter = MlKemParameterSet(parameter_set)
        if parameter != MlKemParameterSet.ML_KEM_768:
            raise NotImplementedError("This CoverCrypt build supports ML-KEM-768; standalone MlKem is independent")
        self._mode = KemMode(mode)
        if config is None:
            path = os.environ.get("HCPABE_COVERCRYPT_CONFIG")
            config = Path(path).read_text(encoding="utf-8") if path else None
        if config is not None:
            if isinstance(config, str):
                config = json.loads(config)
            if not isinstance(config, Mapping):
                raise TypeError("config must be a JSON object or JSON text")
            config = json.dumps(dict(config), ensure_ascii=True)
        self._config_json = config

    @property
    def mode(self) -> KemMode:
        return self._mode

    @property
    def parameter_set(self) -> MlKemParameterSet:
        return MlKemParameterSet.ML_KEM_768

    def setup(self) -> AuthorityKeys:
        if self._config_json is None:
            raise ValueError("Provide CoverCrypt config, or set HCPABE_COVERCRYPT_CONFIG before constructing the object")
        return api.covercrypt_setup(self._config_json, mode=self.mode)

    def setup_with_signing(self, *, ml_dsa_parameter_set: MlDsaParameterSet | None = None) -> AuthoritySigningKeys:
        keys = self.setup()
        parameter = MlDsaParameterSet.ML_DSA_87 if ml_dsa_parameter_set is None else ml_dsa_parameter_set
        verification_key, signing_key = api.ml_dsa_generate_keypair(parameter_set=parameter)
        return AuthoritySigningKeys(*keys, base64.b64encode(verification_key), base64.b64encode(signing_key))

    def add_dimension(self, master_secret_key: bytes, dimension_json: str) -> AuthorityKeys:
        return api.covercrypt_add_dimension_with_mode(master_secret_key, dimension_json, mode=self.mode)

    def add_attribute(self, master_secret_key: bytes, dimension: str, attribute: str,
                      *, after: str | None = None) -> AuthorityKeys:
        """Grow an existing dimension using the native attribute mode."""
        return AuthorityKeys(*legacy.covercrypt_add_attribute_buffer(master_secret_key, dimension, attribute, after))
