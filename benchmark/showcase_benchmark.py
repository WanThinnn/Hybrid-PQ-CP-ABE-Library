#!/usr/bin/env python3
"""
Focused benchmark for public/LinkedIn showcase.

Measures:
- AC17 Buffer API: Setup / KeyGen / Encrypt / Decrypt
- TKN20 Buffer API: Setup / KeyGen / Encrypt / Decrypt
- Charm-Crypto AC17 primitive reference
- AC17/TKN20 + ML-DSA-87 Sign-then-Encrypt overhead
- ML-DSA-87 primitive KeyGen / Sign / Verify

This script intentionally excludes File I/O, payload scaling, policy scaling,
and AES-GCM microbenchmarks to keep the result focused and presentation-ready.

IMPORTANT:
Charm-Crypto AC17 is a primitive reference, not a strict apples-to-apples
equivalent of the native byte-oriented hybrid CP-ABE + AES-GCM pipeline.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
from datetime import datetime
from pathlib import Path

import benchmark_full as bench


def parse_args():
    p = argparse.ArgumentParser(
        description="Focused AC17/TKN20/Charm/PQC showcase benchmark"
    )
    p.add_argument("--profile", choices=bench.PROFILES, default="standard")
    p.add_argument("--iterations", type=int)
    p.add_argument("--warmup", type=int)
    p.add_argument("--payload-bytes", type=int, default=4096)
    p.add_argument("--policy-attributes", type=int, default=12)
    p.add_argument("--repo-root")
    p.add_argument("--lib")
    p.add_argument("--output")
    p.add_argument(
        "--allow-missing-charm",
        action="store_true",
        help="Generate native/PQC results even if Charm-Crypto is unavailable.",
    )
    p.add_argument(
        "--quiet-native",
        action=argparse.BooleanOptionalAction,
        default=True,
    )
    return p.parse_args()


def one(rec, **kwargs):
    rows = rec.find(**kwargs)
    return rows[0] if rows else None


def median(rec):
    return rec.stats["median_ms"]


def make_showcase_charts(rec: bench.Recorder, out: Path, charm_available: bool):
    plt = bench.matplotlib_module()
    charts = out / "charts"
    charts.mkdir(parents=True, exist_ok=True)

    # 1) Core comparison: AC17 Buffer vs TKN20 Buffer vs Charm AC17.
    ops = ["setup", "keygen", "encrypt", "decrypt"]
    series = [
        ("AC17 Buffer", "core", "AC17", "buffer"),
        ("TKN20 Buffer", "core", "TKN20", "buffer"),
    ]
    if charm_available:
        series.append(("Charm-Crypto AC17", "charm_reference", "AC17", "python"))

    fig, ax = plt.subplots(figsize=(11, 6.5))
    x = list(range(len(ops)))
    width = 0.22 if len(series) == 3 else 0.30
    offsets = [-width, 0.0, width] if len(series) == 3 else [-width / 2, width / 2]

    for offset, (label, suite, scheme, mode) in zip(offsets, series):
        vals = []
        for op in ops:
            rows = rec.find(suite=suite, scheme=scheme, mode=mode, operation=op)
            vals.append(median(rows[0]) if rows else 0.0)
        bars = ax.bar([i + offset for i in x], vals, width, label=label)
        for bar, value in zip(bars, vals):
            if value > 0:
                ax.annotate(
                    f"{value:.1f}",
                    (bar.get_x() + bar.get_width() / 2, bar.get_height()),
                    xytext=(0, 3),
                    textcoords="offset points",
                    ha="center",
                    va="bottom",
                    fontsize=8,
                )

    ax.set_xticks(x, ["Setup", "KeyGen", "Encrypt", "Decrypt"])
    ax.set_ylabel("Median latency (ms)")
    ax.set_title("CP-ABE Core Performance — Buffer API")
    ax.text(
        0.5,
        1.01,
        "Charm-Crypto AC17 is a primitive reference; native paths are hybrid byte-oriented implementations.",
        transform=ax.transAxes,
        ha="center",
        va="bottom",
        fontsize=8,
    )
    ax.legend()
    ax.grid(axis="y", alpha=0.2)
    fig.tight_layout()
    fig.savefig(charts / "01_core_buffer_vs_charm.png", dpi=240)
    plt.close(fig)

    # 2) End-to-end PQC overhead.
    labels = ["AC17 Encrypt", "AC17 Decrypt", "TKN20 Encrypt", "TKN20 Decrypt"]
    standard = []
    pqc = []
    mapping = [
        ("AC17", "encrypt", "encrypt_sign"),
        ("AC17", "decrypt", "decrypt_verify"),
        ("TKN20", "encrypt", "encrypt_sign"),
        ("TKN20", "decrypt", "decrypt_verify"),
    ]
    for scheme, std_op, pq_op in mapping:
        std = one(
            rec, suite="core", scheme=scheme, mode="buffer",
            variant="standard", operation=std_op
        )
        pq = one(
            rec, suite="pqc", scheme=scheme, mode="buffer",
            variant="pqc", operation=pq_op
        )
        standard.append(median(std))
        pqc.append(median(pq))

    fig, ax = plt.subplots(figsize=(10, 6.2))
    x = list(range(len(labels)))
    width = 0.36
    bars1 = ax.bar(
        [i - width / 2 for i in x],
        standard,
        width,
        label="CP-ABE + AES-GCM",
    )
    bars2 = ax.bar(
        [i + width / 2 for i in x],
        pqc,
        width,
        label="+ ML-DSA-87 Sign/Verify",
    )
    for bars in (bars1, bars2):
        for bar in bars:
            value = bar.get_height()
            ax.annotate(
                f"{value:.1f}",
                (bar.get_x() + bar.get_width() / 2, value),
                xytext=(0, 3),
                textcoords="offset points",
                ha="center",
                va="bottom",
                fontsize=8,
            )
    ax.set_xticks(x, labels)
    ax.set_ylabel("Median latency (ms)")
    ax.set_title("Post-Quantum Signature Overhead — End-to-End Buffer Path")
    ax.legend()
    ax.grid(axis="y", alpha=0.2)
    fig.tight_layout()
    fig.savefig(charts / "02_pqc_end_to_end.png", dpi=240)
    plt.close(fig)

    # 3) ML-DSA-87 primitive latency.
    keygen = one(rec, suite="mldsa", operation="keygen")
    sign = one(rec, suite="mldsa", operation="sign")
    verify = one(rec, suite="mldsa", operation="verify")
    if keygen and sign and verify:
        values = [median(keygen), median(sign), median(verify)]
        fig, ax = plt.subplots(figsize=(8, 5.5))
        bars = ax.bar(["KeyGen", "Sign", "Verify"], values)
        for bar, value in zip(bars, values):
            ax.annotate(
                f"{value:.3f} ms",
                (bar.get_x() + bar.get_width() / 2, value),
                xytext=(0, 3),
                textcoords="offset points",
                ha="center",
                va="bottom",
                fontsize=9,
            )
        ax.set_ylabel("Median latency (ms)")
        ax.set_title("ML-DSA-87 Primitive Performance")
        ax.grid(axis="y", alpha=0.2)
        fig.tight_layout()
        fig.savefig(charts / "03_mldsa87_primitive.png", dpi=240)
        plt.close(fig)

    # 4) Decrypt distributions.
    groups = []
    group_labels = []
    for scheme in ("AC17", "TKN20"):
        row = one(
            rec, suite="core", scheme=scheme, mode="buffer",
            variant="standard", operation="decrypt"
        )
        if row:
            groups.append(rec.raw_for(row.benchmark_id))
            group_labels.append(f"{scheme} Buffer")

    if charm_available:
        row = one(
            rec, suite="charm_reference", scheme="AC17",
            mode="python", operation="decrypt"
        )
        if row:
            groups.append(rec.raw_for(row.benchmark_id))
            group_labels.append("Charm AC17")

    if groups:
        fig, ax = plt.subplots(figsize=(8.5, 5.8))
        ax.boxplot(groups, tick_labels=group_labels, showfliers=True)
        ax.set_ylabel("Latency (ms)")
        ax.set_title("Decrypt Latency Distribution — Raw Samples")
        ax.grid(axis="y", alpha=0.2)
        fig.tight_layout()
        fig.savefig(charts / "04_decrypt_distribution.png", dpi=240)
        plt.close(fig)


def markdown_table(rows):
    if not rows:
        return "_No data._"
    lines = [
        "| Implementation | Operation | Median (ms) | Mean (ms) | P95 (ms) | P99 (ms) | CV % |",
        "|---|---|---:|---:|---:|---:|---:|",
    ]
    for label, rec in rows:
        s = rec.stats
        lines.append(
            f"| {label} | {rec.operation} | {s['median_ms']:.3f} | "
            f"{s['mean_ms']:.3f} | {s['p95_ms']:.3f} | "
            f"{s['p99_ms']:.3f} | {s['cv_percent']:.2f} |"
        )
    return "\n".join(lines)


def write_showcase_report(
    rec: bench.Recorder,
    out: Path,
    env: dict,
    config: dict,
    charm_available: bool,
):
    core_rows = []
    for scheme in ("AC17", "TKN20"):
        for op in ("setup", "keygen", "encrypt", "decrypt"):
            row = one(
                rec, suite="core", scheme=scheme, mode="buffer",
                variant="standard", operation=op
            )
            if row:
                core_rows.append((f"{scheme} Buffer", row))

    if charm_available:
        for op in ("setup", "keygen", "encrypt", "decrypt"):
            row = one(
                rec, suite="charm_reference", scheme="AC17",
                mode="python", operation=op
            )
            if row:
                core_rows.append(("Charm-Crypto AC17", row))

    pqc_rows = []
    for scheme in ("AC17", "TKN20"):
        for op in ("setup_pqc", "encrypt_sign", "decrypt_verify"):
            row = one(
                rec, suite="pqc", scheme=scheme, mode="buffer",
                variant="pqc", operation=op
            )
            if row:
                pqc_rows.append((f"{scheme} + ML-DSA-87", row))

    mldsa_rows = []
    for op in ("keygen", "sign", "verify"):
        row = one(rec, suite="mldsa", operation=op)
        if row:
            mldsa_rows.append(("ML-DSA-87", row))

    observations = []
    for scheme in ("AC17", "TKN20"):
        std_enc = one(
            rec, suite="core", scheme=scheme, mode="buffer",
            variant="standard", operation="encrypt"
        )
        pq_enc = one(
            rec, suite="pqc", scheme=scheme, mode="buffer",
            variant="pqc", operation="encrypt_sign"
        )
        std_dec = one(
            rec, suite="core", scheme=scheme, mode="buffer",
            variant="standard", operation="decrypt"
        )
        pq_dec = one(
            rec, suite="pqc", scheme=scheme, mode="buffer",
            variant="pqc", operation="decrypt_verify"
        )

        if std_enc and pq_enc:
            delta = (median(pq_enc) - median(std_enc)) / median(std_enc) * 100.0
            observations.append(
                f"- {scheme} Encrypt+Sign median delta: {delta:+.1f}% "
                f"({median(std_enc):.3f} → {median(pq_enc):.3f} ms)."
            )
        if std_dec and pq_dec:
            delta = (median(pq_dec) - median(std_dec)) / median(std_dec) * 100.0
            observations.append(
                f"- {scheme} Decrypt+Verify median delta: {delta:+.1f}% "
                f"({median(std_dec):.3f} → {median(pq_dec):.3f} ms)."
            )

    text = f"""# Hybrid PQ-CP-ABE Showcase Benchmark

Generated: {env.get('timestamp_utc')}

## Scope

This focused run is designed for a concise public performance showcase.

It measures:

- AC17 Buffer API
- TKN20 Buffer API
- Charm-Crypto AC17 reference
- AC17 + ML-DSA-87 Sign-then-Encrypt
- TKN20 + ML-DSA-87 Sign-then-Encrypt
- ML-DSA-87 primitive KeyGen / Sign / Verify

File I/O and scaling suites are intentionally excluded.

## Key observations

{chr(10).join(observations) if observations else "_No derived observations._"}

## Core CP-ABE comparison

{markdown_table(core_rows)}

## PQC Sign-then-Encrypt

{markdown_table(pqc_rows)}

## ML-DSA-87 primitive

{markdown_table(mldsa_rows)}

## Charts

![Core Buffer vs Charm](charts/01_core_buffer_vs_charm.png)

![PQC end-to-end](charts/02_pqc_end_to_end.png)

![ML-DSA-87](charts/03_mldsa87_primitive.png)

![Decrypt distribution](charts/04_decrypt_distribution.png)

## Environment

- CPU: {env.get('cpu')}
- OS: {env.get('os')}
- Logical CPUs: {env.get('logical_cpu_count')}
- Physical CPUs: {env.get('physical_cpu_count', 'n/a')}
- Native library: {env.get('library_version')}
- Python: {env.get('python')}
- Git commit: {env.get('git_commit') or 'n/a'}

## Benchmark configuration

~~~json
{json.dumps(config, indent=2)}
~~~

## Interpretation note

Charm-Crypto AC17 is included as a reference implementation, not as a strict
apples-to-apples end-to-end equivalent. Charm encrypts/decrypts a GT group
element directly, while the native library exposes a byte-oriented hybrid path
that protects a random secret and uses AES-GCM for payload encryption.

AC17/TKN20 CP-ABE remains classical cryptography. The post-quantum component
measured in the hybrid path is the ML-DSA-87 signature layer.

For public claims, use median/p95 values from the full run and publish the raw
samples together with hardware and build information.
"""
    (out / "showcase_report.md").write_text(text, encoding="utf-8")


def main():
    a = parse_args()
    profile = dict(bench.PROFILES[a.profile])
    if a.iterations is not None:
        profile["iterations"] = a.iterations
    if a.warmup is not None:
        profile["warmup"] = a.warmup

    script = Path(__file__).resolve()
    root = bench.repo_root(script, a.repo_root)
    lib = bench.find_lib(root, a.lib)
    native = bench.Native(lib)

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out = (
        Path(a.output).expanduser().resolve()
        if a.output
        else script.parent / "results" / f"showcase_{stamp}"
    )
    out.mkdir(parents=True, exist_ok=True)

    policy = bench.policy_for(a.policy_attributes)
    attrs = bench.attrs_for(a.policy_attributes)
    payload = os.urandom(a.payload_bytes)

    rec = bench.Recorder()
    env = bench.environment(native, root)
    config = {
        "mode": "showcase",
        "profile": a.profile,
        "iterations": profile["iterations"],
        "warmup": profile["warmup"],
        "micro_iterations": profile["micro_iterations"],
        "payload_bytes": a.payload_bytes,
        "policy_attributes": a.policy_attributes,
        "policy": policy,
        "library_path": str(lib),
        "repo_root": str(root) if root else None,
        "charm_required": not a.allow_missing_charm,
    }

    print("=" * 72)
    print("Hybrid PQ-CP-ABE Showcase Benchmark")
    print("=" * 72)
    print(f"Library: {lib}")
    print(f"Version: {native.version()}")
    print(f"Payload: {bench.human_bytes(a.payload_bytes)}")
    print(f"Policy:  {a.policy_attributes} distinct attributes")
    print()

    print("[1/4] Native Buffer APIs — AC17 / TKN20")
    for scheme in (bench.AC17, bench.TKN20):
        bench.run_core_buffer(
            native, rec, scheme, payload, policy, attrs,
            a.policy_attributes, profile["iterations"], profile["warmup"],
            a.quiet_native,
        )

    print("[2/4] Post-Quantum Sign-then-Encrypt — ML-DSA-87")
    for scheme in (bench.AC17, bench.TKN20):
        bench.run_pqc_buffer(
            native, rec, scheme, payload, policy, attrs,
            a.policy_attributes, profile["iterations"], profile["warmup"],
            a.quiet_native,
        )

    print("[3/4] ML-DSA-87 primitive")
    bench.run_mldsa(
        native, rec, [a.payload_bytes],
        profile["micro_iterations"], profile["warmup"], a.quiet_native,
    )

    print("[4/4] Charm-Crypto AC17 reference")
    charm_available = bench.run_charm(
        rec,
        profile["iterations"],
        profile["warmup"],
        policy,
        a.policy_attributes,
    )

    if not charm_available and not a.allow_missing_charm:
        shutil.rmtree(out, ignore_errors=True)
        raise RuntimeError(
            "Charm-Crypto is required for showcase mode but is unavailable. "
            "Install Charm-Crypto or rerun with --allow-missing-charm."
        )

    bench.write_data(rec, out, env, config)
    make_showcase_charts(rec, out, charm_available)
    write_showcase_report(rec, out, env, config, charm_available)

    print()
    print("Showcase benchmark complete.")
    print(f"Report: {out / 'showcase_report.md'}")
    print(f"Summary: {out / 'summary.csv'}")
    print(f"Raw: {out / 'raw_samples.csv'}")
    print(f"Charts: {out / 'charts'}")


if __name__ == "__main__":
    main()
