from __future__ import annotations

import csv
import json
from dataclasses import asdict
from datetime import datetime
from .config import SCHEMES

def human_bytes(n: int) -> str:
    value = float(n)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if value < 1024 or unit == "GiB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.2f} {unit}"
        value /= 1024
    return str(n)


def write_data(rec, out, env, config):
    with (out / "raw_samples.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["benchmark_id", "sample_index", "latency_ms"])
        w.writeheader()
        w.writerows(rec.raw)

    fields = [
        "benchmark_id", "suite", "scheme", "mode", "variant", "operation", "case",
        "payload_bytes", "policy_attributes", "count", "min_ms", "mean_ms",
        "median_ms", "p95_ms", "p99_ms", "max_ms", "stdev_ms", "cv_percent",
        "mean_ci95_low_ms", "mean_ci95_high_ms", "extra_json"
    ]
    with (out / "summary.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for r in rec.records:
            row = {
                "benchmark_id": r.benchmark_id, "suite": r.suite,
                "scheme": r.scheme, "mode": r.mode, "variant": r.variant,
                "operation": r.operation, "case": r.case,
                "payload_bytes": r.payload_bytes,
                "policy_attributes": r.policy_attributes,
                **r.stats, "extra_json": json.dumps(r.extra, sort_keys=True)
            }
            w.writerow(row)

    payload = {"environment": env, "config": config, "records": [asdict(r) for r in rec.records]}
    (out / "benchmark_results.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")


def table(rows):
    if not rows:
        return "No data.\n"
    out = [
        "| Scheme | Mode | Variant | Operation | Case | Median ms | Mean ms | P95 ms | P99 ms | CV % |",
        "|---|---|---|---|---|---:|---:|---:|---:|---:|",
    ]
    for r in rows:
        s = r.stats
        out.append(
            f"| {r.scheme} | {r.mode} | {r.variant} | {r.operation} | {r.case} | "
            f"{s['median_ms']:.3f} | {s['mean_ms']:.3f} | {s['p95_ms']:.3f} | "
            f"{s['p99_ms']:.3f} | {s['cv_percent']:.2f} |"
        )
    return "\n".join(out) + "\n"


def one(rec, **kwargs):
    rows = rec.find(**kwargs)
    return rows[0] if rows else None


def report(rec, out, env, config, charm):
    findings = []
    for scheme in SCHEMES.values():
        f = one(rec, suite="core", scheme=scheme, mode="file", operation="decrypt")
        b = one(rec, suite="core", scheme=scheme, mode="buffer", operation="decrypt")
        if f and b and b.stats["median_ms"]:
            delta = (b.stats["median_ms"] - f.stats["median_ms"]) / f.stats["median_ms"] * 100.0
            findings.append(
                f"- {scheme} decrypt median: Buffer {b.stats['median_ms']:.3f} ms; "
                f"File I/O {f.stats['median_ms']:.3f} ms; Buffer-vs-File delta {delta:+.1f}%."
            )
        se = one(rec, suite="core", scheme=scheme, mode="buffer", operation="encrypt")
        pe = one(rec, suite="pqc", scheme=scheme, mode="buffer", operation="encrypt_sign")
        sd = one(rec, suite="core", scheme=scheme, mode="buffer", operation="decrypt")
        pd = one(rec, suite="pqc", scheme=scheme, mode="buffer", operation="decrypt_verify")
        if se and pe:
            pct = (pe.stats["median_ms"] - se.stats["median_ms"]) / se.stats["median_ms"] * 100
            findings.append(f"- {scheme} Encrypt+Sign overhead: {pct:+.1f}% median.")
        if sd and pd:
            pct = (pd.stats["median_ms"] - sd.stats["median_ms"]) / sd.stats["median_ms"] * 100
            findings.append(f"- {scheme} Decrypt+Verify overhead: {pct:+.1f}% median.")

    env_table = "\n".join([
        "| Item | Value |", "|---|---|",
        f"| OS | {env.get('os')} |",
        f"| CPU | {env.get('cpu')} |",
        f"| Logical CPUs | {env.get('logical_cpu_count')} |",
        f"| Physical CPUs | {env.get('physical_cpu_count', 'n/a')} |",
        f"| Library | {env.get('library_version')} |",
        f"| Python | {env.get('python')} |",
        f"| Python bindings | {env.get('python_binding_version')} |",
        f"| Benchmark API | {env.get('benchmark_api')} |",
        f"| Git commit | {env.get('git_commit') or 'n/a'} |",
        f"| Git dirty | {env.get('git_dirty')} |",
    ])

    text = f"""# Hybrid PQ-CP-ABE Performance Benchmark Report

Generated: {env.get('timestamp_utc')}

## Executive summary

This run measures native AC17/TKN20/CoverCrypt performance, File I/O versus
Buffer APIs, ML-DSA-87 Sign-then-Encrypt overhead, ML-DSA and AES-GCM primitives,
policy complexity scaling, and payload-size scaling.

{chr(10).join(findings) if findings else "No derived findings available."}

## Methodology

- High-resolution monotonic timer: time.perf_counter_ns.
- Warm-up iterations are discarded.
- All measured samples are preserved in raw_samples.csv.
- No outlier removal is performed.
- Primary statistic: median latency.
- Also reported: mean, standard deviation, p95, p99, coefficient of variation,
  and a 95% normal-approximation confidence interval for the mean.
- Python cyclic GC is disabled only inside timed loops.
- File mode intentionally includes library disk I/O.
- Buffer mode keeps key/data transfer in memory.
- Timings include Python API validation and conversion overhead.
- AES encryption uses a fresh nonce for every call; nonce generation is outside the timer.
- Timer boundaries exclude progress output, GC collection and log redirection.
- Every benchmark family performs a correctness check.
- AC17/TKN20/Charm use {config['policy_attributes']} logical terms in the baseline policy.
- CoverCrypt maps the same logical-term count across {config['covercrypt_dimension_count_effective']} dimensions,
  OR within each dimension and AND between dimensions; this is not the same policy shape.
- Baseline payload: {human_bytes(config['payload_bytes'])}.

## Charm-Crypto reference

{"Charm-Crypto AC17 was available." if charm else "Charm-Crypto was disabled or unavailable and skipped."}

Charm-Crypto is reported inside the primitive-comparison suite as a reference,
not as a byte-for-byte equivalent. Charm AC17 encrypts a GT group element.
The modern Python objects AC17CPABE, TKN20CPABE and CoverCryptABE encrypt
the same 32-byte key material through the public hybrid API. These measurements
include Python binding overhead, serialization, key derivation and AES-GCM;
they are not isolated ABE primitive or C++ bridge timings. Universal speedup claims must not be
inferred without this scope note.

## Environment

{env_table}

## Configuration

```json
{json.dumps(config, indent=2)}
```

## Python API key-protection comparison

{table(rec.find(suite="primitive_compare"))}

Native AC17, TKN20, and CoverCrypt protect/recover the same 32-byte key material.
CoverCrypt runs in hybridized mode (Curve25519 + ML-KEM-768). All native
comparison operations use the modern Python hybrid API, including serialization
and symmetric encryption overhead. Historical C++ bridge timings are not comparable. Charm-Crypto AC17 is a GT-element reference and is not
byte-for-byte equivalent.

## Native core

{table(rec.find(suite="core"))}

## PQC Sign-then-Encrypt

{table(rec.find(suite="pqc"))}

## ML-DSA-87

{table(rec.find(suite="mldsa"))}

## AES-256-GCM

{table(rec.find(suite="aes_gcm"))}

## Policy scaling

{table(rec.find(suite="policy_scaling"))}

## Payload scaling

{table(rec.find(suite="payload_scaling"))}

## Charts

![ABE primitive comparison](charts/00_abe_primitive_comparison.png)

![ABE primitive comparison - log scale](charts/00_abe_primitive_comparison_log.png)

![Core latency](charts/01_core_latency.png)

![Core latency - log scale](charts/01_core_latency_log.png)

![Decrypt distribution](charts/02_decrypt_distribution.png)

![PQC overhead](charts/03_pqc_overhead.png)

![Policy scaling](charts/04_policy_scaling.png)

![Payload scaling](charts/05_payload_scaling.png)

![ML-DSA latency](charts/06_mldsa_latency.png)

![AES-GCM throughput](charts/07_aes_gcm_throughput.png)

## Limitations

1. Results are specific to this machine, compiler build, CPU power state,
   thermal state, OS scheduling, and background load.
2. File I/O results may be affected by filesystem cache and antivirus.
3. Buffer measurements are the stronger signal for cryptographic hot-path
   latency because they remove most disk overhead.
4. One local benchmark is not a substitute for independent third-party testing.
5. For publishable claims, rerun on multiple machines and publish raw_samples.csv
   together with compiler/build flags.
6. AC17/TKN20 remain classical pairing/discrete-log cryptography. CoverCrypt
   is benchmarked in this repository's default hybridized mode
   (Curve25519 + ML-KEM-768). ML-DSA-87 remains the optional signature layer.
"""
    text = "\n".join(
        line for line in text.splitlines()
        if not line.startswith("![") or (out / line.split("](", 1)[1].rstrip(")")).is_file()
    ) + "\n"
    (out / "report.md").write_text(text, encoding="utf-8")


def write_snapshot_readme(out, env, config, charm):
    date = datetime.now().strftime("%Y-%m-%d")
    showcase = bool(config.get("showcase"))
    charm_requirement = " --require-charm" if config.get("require_charm") else ""
    scope = (
        "AC17, TKN20, and CoverCrypt use the in-memory Buffer API. "
        "CoverCrypt runs in hybridized mode (Curve25519 + ML-KEM-768)."
        if showcase else
        "AC17, TKN20, and CoverCrypt include the configured benchmark suites. "
        "CoverCrypt runs in hybridized mode (Curve25519 + ML-KEM-768)."
    )
    text = f"""# Published Benchmark — {date}

This directory contains a reproducible benchmark snapshot for Hybrid PQ-CP-ABE Library v{env.get('library_version')}.

## Environment

- CPU: {env.get('cpu')}
- OS: {env.get('os')}
- Python: {env.get('python')}
- Native library: v{env.get('library_version')}
- Git commit: {env.get('git_commit') or 'n/a'}
- Benchmark profile: {config.get('profile')}
- Timed iterations: {config.get('iterations')}
- Warm-up iterations: {config.get('warmup')}
- Payload: {human_bytes(config.get('payload_bytes', 0))}
- Policy terms: {config.get('policy_attributes')}
- CoverCrypt dimensions: {config.get('covercrypt_dimension_count_effective')} (requested {config.get('covercrypt_dimension_count_requested')})
- CoverCrypt rights-universe estimate: {config.get('covercrypt_rights_universe_estimate')}
- Mode: {'showcase' if showcase else 'comprehensive'}

## Included artifacts

- `report.md` — methodology, environment, summary tables, and interpretation notes.
- `summary.csv` — aggregated median/mean/p95/p99/CV statistics.
- `raw_samples.csv` — every recorded timing sample; no outlier removal.
- `benchmark_results.json` — machine-readable benchmark metadata and aggregate records.
- `covercrypt_config.json` — persisted CoverCrypt dimensions used by this run.
- `charts/` — generated benchmark figures.

## Scope

{scope}

The PQC measurements cover the end-to-end Sign-then-Encrypt path using ML-DSA-87.

Charm-Crypto AC17 is {'included' if charm else 'disabled or unavailable and therefore skipped'} as the GT-element reference in the primitive-comparison suite. Native AC17/TKN20/CoverCrypt protect the same 32-byte key material.

## Reproduce

From the repository `benchmark/` directory:

```bash
python main.py --profile {config.get('profile')}{' --showcase' if showcase else ''} --iterations {config.get('iterations')} --warmup {config.get('warmup')} --payload-bytes {config.get('payload_bytes')} --policy-attributes {config.get('policy_attributes')} --covercrypt-dimensions {config.get('covercrypt_dimension_count_requested')} --seed {config.get('seed')}{' --no-file' if not config.get('include_file') else ''}{' --no-pqc' if not config.get('include_pqc') else ''}{' --no-micro' if not config.get('include_micro') else ''}{' --no-scaling' if not config.get('include_scaling') else ''}{' --no-charm' if not config.get('include_charm') else ''}{' --no-primitive' if not config.get('include_primitive') else ''}{charm_requirement}
```

For a broader benchmark including File I/O, scaling tests, AES-GCM, and additional microbenchmarks:

```bash
python main.py --profile full
```
"""
    (out / "README.md").write_text(text, encoding="utf-8")
