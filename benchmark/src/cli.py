from __future__ import annotations

import argparse
import json
import math
import os
import random
import shutil
from datetime import datetime
from pathlib import Path
from .config import (PROFILES, NATIVE_SCHEMES, COVERCRYPT, policy_for, attrs_for,
                     covercrypt_policy_attrs, configure_covercrypt)
from .native import Native, repo_root
from .environment import detect_cpu_model, published_cpu_slug, environment
from .records import Recorder
from .charts import make_charts
from .reports import write_data, report, write_snapshot_readme
from .suites import (load_charm, run_native_comparison, run_charm, run_core_buffer, run_core_file,
                     run_pqc_buffer, run_mldsa, run_aes, run_policy_scaling, run_payload_scaling)

def args():
    p = argparse.ArgumentParser(description="Hybrid PQ-CP-ABE comprehensive benchmark")
    p.add_argument("--profile", choices=PROFILES, default="standard")
    p.add_argument("--showcase", action="store_true", help="Run focused primitive/Buffer/PQC/ML-DSA/Charm showcase only")
    p.add_argument("--repo-root")
    p.add_argument("--output", help="Override published snapshot directory")
    p.add_argument("--iterations", type=int)
    p.add_argument("--warmup", type=int)
    p.add_argument("--payload-bytes", type=int, default=4096)
    p.add_argument("--policy-attributes", type=int, default=12)
    p.add_argument("--covercrypt-dimensions", type=int, default=4,
                   help="Number of CoverCrypt policy dimensions (default: 4)")
    p.add_argument("--seed", type=int, default=2026)
    p.add_argument("--no-file", action="store_true")
    p.add_argument("--no-pqc", action="store_true")
    p.add_argument("--no-micro", action="store_true")
    p.add_argument("--no-scaling", action="store_true")
    p.add_argument("--no-charm", action="store_true")
    p.add_argument("--require-charm", action="store_true",
                   help="Fail before measurements if Charm-Crypto cannot be imported")
    p.add_argument("--no-primitive", action="store_true", help="Skip modern Python API 32-byte comparison suite")
    p.add_argument("--quiet-native", action=argparse.BooleanOptionalAction, default=True)
    a = p.parse_args()
    if a.no_charm and a.require_charm:
        p.error("--no-charm and --require-charm cannot be combined")
    return a


def main():
    a = args()
    profile = dict(PROFILES[a.profile])
    if a.iterations is not None:
        profile["iterations"] = a.iterations
    if a.warmup is not None:
        profile["warmup"] = a.warmup
    if profile["iterations"] < 1 or profile["warmup"] < 0:
        raise ValueError("iterations must be positive and warmup nonnegative")
    if a.policy_attributes < 1 or a.payload_bytes < 1 or a.covercrypt_dimensions < 1:
        raise ValueError("policy attributes, payload bytes, and CoverCrypt dimensions must be positive")

    script = Path(__file__).resolve().parents[1] / "main.py"
    root = repo_root(script, a.repo_root)
    if a.require_charm:
        try:
            load_charm()
        except Exception as exc:
            raise RuntimeError("Charm-Crypto is required for the four-way comparison; install it in this Python environment") from exc

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    if a.output:
        out = Path(a.output).expanduser().resolve()
    else:
        published_root = (root / "benchmark" if root else script.parent) / "published"
        out = published_root / (
            f"{datetime.now().strftime('%Y-%m-%d')}_"
            f"{published_cpu_slug(detect_cpu_model())}_{a.profile}_{stamp}"
        )
    if out.exists() and any(out.iterdir()):
        raise FileExistsError(f"Output directory is not empty: {out}")
    out.mkdir(parents=True, exist_ok=True)
    tmp = out / "_tmp"
    tmp.mkdir(exist_ok=True)

    max_covercrypt_attributes = max(
        [a.policy_attributes] + (profile["policy_sizes"] if not a.no_scaling and not a.showcase else [])
    )
    covercrypt_config = configure_covercrypt(
        out, max_covercrypt_attributes, a.covercrypt_dimensions, "covercrypt_config.json"
    )
    covercrypt_dimensions = json.loads(covercrypt_config.read_text(encoding="utf-8"))["dimensions"]
    # Configure the environment before loading the native library. In particular,
    # Windows DLLs may initialize their C runtime's environment when loaded.
    native = Native(root, json.loads(covercrypt_config.read_text(encoding="utf-8")))

    policy = policy_for(a.policy_attributes)
    attrs = attrs_for(a.policy_attributes)
    payload = os.urandom(a.payload_bytes)

    config = {
        **profile,
        "profile": a.profile,
        "payload_bytes": a.payload_bytes,
        "policy_attributes": a.policy_attributes,
        "policy": policy,
        "attributes": attrs,
        "seed": a.seed,
        "showcase": a.showcase,
        "include_file": (not a.no_file) and not a.showcase,
        "include_pqc": not a.no_pqc,
        "include_micro": not a.no_micro,
        "include_scaling": (not a.no_scaling) and not a.showcase,
        "include_charm": not a.no_charm,
        "require_charm": a.require_charm,
        "include_primitive": not a.no_primitive,
        "benchmark_api": "pq_cp_abe modern Python API (6.1)",
        "comparison_semantics": "native hybrid encryption of 32 bytes vs Charm GT reference",
        "primitive_key_material_bytes": 32,
        "covercrypt_mode": "hybridized",
        "covercrypt_config": str(covercrypt_config),
        "covercrypt_dimensions": covercrypt_dimensions,
        "covercrypt_dimension_count_requested": a.covercrypt_dimensions,
        "covercrypt_dimension_count_effective": len(covercrypt_dimensions),
        "covercrypt_rights_universe_estimate": math.prod(
            len(dimension["attributes"]) + 1 for dimension in covercrypt_dimensions
        ),
        "covercrypt_policy_shape": "OR within each dimension, AND between dimensions",
        "covercrypt_max_policy_attributes": max_covercrypt_attributes,
        "library_path": native.path,
        "repo_root": str(root) if root else None,
    }
    env = environment(native, root)
    rec = Recorder()

    print("=" * 70)
    print("Hybrid PQ-CP-ABE Showcase Benchmark" if a.showcase else "Hybrid PQ-CP-ABE Comprehensive Benchmark")
    print("=" * 70)
    print(f"Library: {native.path}")
    print(f"Version: {native.version}")
    print(f"Profile: {a.profile}")
    print(f"Output:  {out}")
    print(
        f"CoverCrypt: hybridized, {len(covercrypt_dimensions)} dimension(s), "
        f"{max_covercrypt_attributes} configured attributes"
    )
    print(f"CoverCrypt config: {covercrypt_config}")

    schemes = list(NATIVE_SCHEMES)
    random.Random(a.seed).shuffle(schemes)

    try:
        print("[1/6] ABE key-protection primitive comparison")
        if not a.no_primitive:
            for scheme in schemes:
                scheme_policy, scheme_attrs = (
                    covercrypt_policy_attrs(a.policy_attributes, a.covercrypt_dimensions)
                    if scheme == COVERCRYPT
                    else (policy, attrs)
                )
                run_native_comparison(
                    native, rec, scheme, scheme_policy, scheme_attrs,
                    a.policy_attributes, profile["iterations"], profile["warmup"],
                    a.quiet_native,
                )
        charm = False if a.no_charm else run_charm(
            rec, profile["iterations"], profile["warmup"], policy, a.policy_attributes
        )
        config["charm_available"] = charm

        print("[2/6] Native production core")
        for scheme in schemes:
            scheme_policy, scheme_attrs = (
                covercrypt_policy_attrs(a.policy_attributes, a.covercrypt_dimensions)
                if scheme == COVERCRYPT
                else (policy, attrs)
            )
            run_core_buffer(native, rec, scheme, payload, scheme_policy, scheme_attrs, a.policy_attributes, profile["iterations"], profile["warmup"], a.quiet_native)
            if not a.no_file and not a.showcase:
                run_core_file(native, rec, scheme, payload, scheme_policy, scheme_attrs, a.policy_attributes, profile["iterations"], profile["warmup"], a.quiet_native, tmp)

        print("[3/6] PQC Sign-then-Encrypt")
        if not a.no_pqc:
            for scheme in schemes:
                scheme_policy, scheme_attrs = (
                    covercrypt_policy_attrs(a.policy_attributes, a.covercrypt_dimensions)
                    if scheme == COVERCRYPT
                    else (policy, attrs)
                )
                run_pqc_buffer(native, rec, scheme, payload, scheme_policy, scheme_attrs, a.policy_attributes, profile["iterations"], profile["warmup"], a.quiet_native)

        print("[4/6] Primitive microbenchmarks")
        if not a.no_micro:
            if not a.no_pqc:
                mldsa_sizes = [a.payload_bytes] if a.showcase else profile["micro_sizes"]
                run_mldsa(native, rec, mldsa_sizes, profile["micro_iterations"], profile["warmup"], a.quiet_native)
            if not a.showcase:
                run_aes(native, rec, profile["micro_sizes"], profile["micro_iterations"], profile["warmup"], a.quiet_native)

        print("[5/6] Scaling")
        if not a.no_scaling and not a.showcase:
            run_policy_scaling(native, rec, profile["policy_sizes"], profile["scale_iterations"], profile["warmup"], a.quiet_native, a.covercrypt_dimensions)
            run_payload_scaling(native, rec, profile["payload_sizes"], profile["scale_iterations"], profile["warmup"], a.quiet_native, a.policy_attributes, not a.no_pqc, a.covercrypt_dimensions)

        print("[6/6] Outputs")
        write_data(rec, out, env, config)
        make_charts(rec, out)
        report(rec, out, env, config, charm)
        write_snapshot_readme(out, env, config, charm)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print("Done.")
    print(f"Report: {out / 'report.md'}")
    print(f"Raw:    {out / 'raw_samples.csv'}")
    print(f"Charts: {out / 'charts'}")
