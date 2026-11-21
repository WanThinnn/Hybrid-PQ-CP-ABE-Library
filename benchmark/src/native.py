"""Load the public Python bindings once; leave C ABI ownership to the package."""
from __future__ import annotations

import os
import re
import sys
from pathlib import Path

from .config import AC17, TKN20, COVERCRYPT


def repo_root(script: Path, explicit: str | None) -> Path | None:
    configured = explicit or os.environ.get("HYBRID_CPABE_ROOT")
    if configured:
        root = Path(configured).expanduser().resolve()
        if not (root / "bindings" / "python" / "pq_cp_abe").is_dir():
            raise ValueError(f"Not a pq-cp-abe repository: {root}")
        return root
    for candidate in script.resolve().parents:
        if (candidate / "bindings" / "python" / "pq_cp_abe").is_dir():
            return candidate
    return None


class Native:
    def __init__(self, root: Path | None, covercrypt_config: dict):
        # Import only after CLI parsing and CoverCrypt file-mode configuration.
        if root:
            sys.path.insert(0, str(root / "bindings" / "python"))
        import pq_cp_abe as pq
        from pq_cp_abe.api import functional

        self.api = functional
        self.version = pq.get_version()
        self.binding_version = pq.__version__
        self.path = str(Path(pq.native._name).resolve())
        for label, version in (("Native library", self.version),
                               ("Python bindings", self.binding_version)):
            match = re.match(r"(\d+)\.(\d+)", version)
            if not match or tuple(map(int, match.groups())) < (6, 1):
                raise RuntimeError(f"{label} 6.1+ required; loaded {version}")
        self.backends = {
            AC17: pq.AC17CPABE(),
            TKN20: pq.TKN20CPABE(),
            COVERCRYPT: pq.CoverCryptABE(config=covercrypt_config, mode=pq.KemMode.HYBRIDIZED),
        }
        self.signer = pq.MlDsa(pq.MlDsaParameterSet.ML_DSA_87)
        self.aes = pq.AesGcm(256)

    def backend(self, scheme):
        return self.backends[scheme]
