from __future__ import annotations

import json
import os
from pathlib import Path


AC17 = 0
TKN20 = 1
COVERCRYPT = 2
OK = 0
SCHEMES = {AC17: "AC17", TKN20: "TKN20", COVERCRYPT: "CoverCrypt"}
NATIVE_SCHEMES = (AC17, TKN20, COVERCRYPT)

PROFILES = {
    "quick": {
        "iterations": 20,
        "warmup": 2,
        "micro_iterations": 50,
        "scale_iterations": 10,
        "policy_sizes": [1, 6, 12],
        "payload_sizes": [1024, 65536],
        "micro_sizes": [1024, 65536],
    },
    "standard": {
        "iterations": 100,
        "warmup": 5,
        "micro_iterations": 250,
        "scale_iterations": 30,
        "policy_sizes": [1, 3, 6, 12],
        "payload_sizes": [1024, 65536, 1048576],
        "micro_sizes": [1024, 65536, 1048576],
    },
    "full": {
        "iterations": 500,
        "warmup": 20,
        "micro_iterations": 1000,
        "scale_iterations": 100,
        "policy_sizes": [1, 3, 6, 12, 24],
        "payload_sizes": [1024, 65536, 1048576, 8388608],
        "micro_sizes": [1024, 65536, 1048576, 8388608],
    },
}

def policy_for(n: int) -> str:
    attrs = [f"ATTR{i}" for i in range(1, n + 1)]
    expr = attrs[0]
    for attr in attrs[1:]:
        expr = f"({expr} AND {attr})"
    return expr


def attrs_for(n: int) -> str:
    attrs = [f"ATTR{i}" for i in range(1, n + 1)]
    attrs += [f"EXTRA{i}" for i in range(1, 5)]
    return " ".join(attrs)


def covercrypt_distribution(n: int, dimension_count: int) -> list[int]:
    """Distribute N logical policy terms as evenly as possible across dimensions."""
    n = max(1, n)
    dimension_count = max(1, min(dimension_count, n))
    base, remainder = divmod(n, dimension_count)
    return [base + (1 if index < remainder else 0) for index in range(dimension_count)]


def covercrypt_policy_attrs(n: int, dimension_count: int = 4) -> tuple[str, str]:
    """Map N logical terms onto CoverCrypt-native policy dimensions.

    CoverCrypt dimensions are policy axes, not independent boolean attributes.
    Modeling every AC17/TKN20 attribute as its own {present,absent} dimension
    makes the rights universe grow combinatorially. The benchmark therefore
    distributes logical terms across a bounded number of dimensions, OR within
    each dimension and AND between dimensions.
    """
    counts = covercrypt_distribution(n, dimension_count)
    clauses = []
    granted = []
    for dimension_index, count in enumerate(counts, start=1):
        name = f"BENCH_D{dimension_index}"
        terms = [f"{name}::V{value_index}" for value_index in range(1, count + 1)]
        clauses.append(terms[0] if len(terms) == 1 else "(" + " || ".join(terms) + ")")
        granted.append(terms[0])
    return " && ".join(clauses), " ".join(granted)


def configure_covercrypt(
    directory: Path,
    max_policy_attributes: int,
    dimension_count: int = 4,
    filename: str = "covercrypt.json",
) -> Path:
    counts = covercrypt_distribution(max_policy_attributes, dimension_count)
    dimensions = [
        {
            "name": f"BENCH_D{dimension_index}",
            "attributes": [f"V{i}" for i in range(1, count + 1)],
        }
        for dimension_index, count in enumerate(counts, start=1)
    ]
    config_path = directory / filename
    config_path.write_text(
        json.dumps({"dimensions": dimensions}, indent=2),
        encoding="utf-8",
    )
    os.environ["HCPABE_COVERCRYPT_CONFIG"] = str(config_path.resolve())
    os.environ["HCPABE_COVERCRYPT_MODE"] = "hybridized"
    return config_path


def adaptive_iterations(base: int, size: int) -> int:
    if size >= 8388608:
        return min(base, 20)
    if size >= 1048576:
        return min(base, 50)
    if size >= 65536:
        return min(base, 100)
    return base
