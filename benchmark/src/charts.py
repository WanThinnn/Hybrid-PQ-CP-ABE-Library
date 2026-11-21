from __future__ import annotations

import math
from pathlib import Path
from typing import Any, Callable
from .config import SCHEMES

def matplotlib_module():
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    return plt


def _chart_series_data(rows, preferred_series, series_key):
    data: dict[str, dict[str, float]] = {}
    for row in rows:
        label = series_key(row)
        data.setdefault(label, {})[row.operation] = row.stats["median_ms"]

    series = [label for label in preferred_series if label in data]
    series.extend(sorted(label for label in data if label not in series))
    return data, series


def _plot_grouped_medians(
    plt,
    rows,
    output_path: Path,
    title: str,
    subtitle: str,
    operations: list[tuple[str, str]],
    preferred_series: list[str],
    series_key: Callable[[Any], str],
    dpi: int = 240,
    log_scale: bool = False,
):
    """Plot only series/operations that actually exist; never synthesize zero bars."""
    data, series = _chart_series_data(rows, preferred_series, series_key)
    if not series:
        return False

    positive_values = [
        value
        for label in series
        for value in data[label].values()
        if value is not None and math.isfinite(value) and value > 0
    ]
    if not positive_values:
        return False

    x = list(range(len(operations)))
    width = min(0.8 / len(series), 0.22)
    fig_width = max(11.0, 2.15 * len(operations) + 0.85 * len(series))
    fig, ax = plt.subplots(figsize=(fig_width, 6.5))

    for idx, label in enumerate(series):
        offset = (idx - (len(series) - 1) / 2) * width
        bar_x = []
        values = []
        for op_index, (operation, _) in enumerate(operations):
            value = data[label].get(operation)
            if value is None or not math.isfinite(value) or value <= 0:
                continue
            bar_x.append(op_index + offset)
            values.append(value)

        if not values:
            continue

        bars = ax.bar(bar_x, values, width, label=label)
        for bar, value in zip(bars, values):
            ax.annotate(
                f"{value:.1f}" if value >= 10 else f"{value:.2f}",
                (bar.get_x() + bar.get_width() / 2, bar.get_height()),
                xytext=(0, 4),
                textcoords="offset points",
                ha="center",
                va="bottom",
                fontsize=7,
            )

    ax.set_xticks(x, [label for _, label in operations])
    ax.set_ylabel("Median latency (ms)")
    if log_scale:
        minimum = min(positive_values)
        maximum = max(positive_values)
        ax.set_yscale("log")
        ax.set_ylim(bottom=max(minimum / 1.8, 1e-3), top=maximum * 1.45)
        ax.set_ylabel("Median latency (ms, log scale)")

    fig.suptitle(title, fontsize=15, y=0.985)
    if subtitle:
        fig.text(0.5, 0.945, subtitle, ha="center", va="top", fontsize=8.5)

    ax.legend(fontsize=9)
    ax.grid(axis="y", alpha=0.2)
    fig.tight_layout(rect=[0, 0, 1, 0.91])
    fig.savefig(output_path, dpi=dpi)
    plt.close(fig)
    return True


def make_charts(rec, out):
    plt = matplotlib_module()
    charts = out / "charts"
    charts.mkdir(exist_ok=True)

    primitive = rec.find(suite="primitive_compare")
    if primitive:
        primitive_ops = [
            ("setup", "Setup"),
            ("keygen", "KeyGen"),
            ("protect", "Protect"),
            ("recover", "Recover"),
        ]
        primitive_series = ["AC17", "TKN20", "CoverCrypt", "Charm-Crypto AC17"]
        primitive_subtitle = (
            "Native Python hybrid APIs encrypt 32 bytes; "
            "Charm-Crypto AC17 uses a GT-element reference."
        )
        _plot_grouped_medians(
            plt,
            primitive,
            charts / "00_abe_primitive_comparison.png",
            "Python API Key-Protection Comparison",
            primitive_subtitle,
            primitive_ops,
            primitive_series,
            lambda row: row.scheme,
            dpi=240,
        )
        _plot_grouped_medians(
            plt,
            primitive,
            charts / "00_abe_primitive_comparison_log.png",
            "Python API Key-Protection Comparison",
            primitive_subtitle + " Log scale exposes low-latency candidates.",
            primitive_ops,
            primitive_series,
            lambda row: row.scheme,
            dpi=240,
            log_scale=True,
        )

    core = rec.find(suite="core")
    if core:
        core_ops = [
            ("setup", "Setup"),
            ("keygen", "KeyGen"),
            ("encrypt", "Encrypt"),
            ("decrypt", "Decrypt"),
        ]
        preferred_core_series = [
            f"{scheme} {mode}"
            for scheme in SCHEMES.values()
            for mode in ("file", "buffer")
        ]
        core_subtitle = (
            "Only series present in this run are shown; missing modes are omitted, "
            "not plotted as 0 ms."
        )
        _plot_grouped_medians(
            plt,
            core,
            charts / "01_core_latency.png",
            "Native CP-ABE Core Performance",
            core_subtitle,
            core_ops,
            preferred_core_series,
            lambda row: f"{row.scheme} {row.mode}",
            dpi=220,
        )
        _plot_grouped_medians(
            plt,
            core,
            charts / "01_core_latency_log.png",
            "Native CP-ABE Core Performance",
            core_subtitle + " Log scale exposes low-latency candidates.",
            core_ops,
            preferred_core_series,
            lambda row: f"{row.scheme} {row.mode}",
            dpi=220,
            log_scale=True,
        )

        core_series = []
        for scheme in SCHEMES.values():
            for mode in ("file", "buffer"):
                if any(row.scheme == scheme and row.mode == mode for row in core):
                    core_series.append((scheme, mode))

        fig, ax = plt.subplots(figsize=(9, 6))
        groups, labels = [], []
        for scheme, mode in core_series:
            rows = rec.find(suite="core", scheme=scheme, mode=mode, operation="decrypt")
            if rows:
                groups.append(rec.raw_for(rows[0].benchmark_id))
                labels.append(f"{scheme}\n{mode}")
        ax.boxplot(groups, tick_labels=labels, showfliers=True)
        ax.set_ylabel("Latency (ms)")
        ax.set_title("Decrypt Latency Distribution - Raw Samples")
        ax.grid(axis="y", alpha=0.2)
        fig.tight_layout()
        fig.savefig(charts / "02_decrypt_distribution.png", dpi=220)
        plt.close(fig)

    pq = rec.find(suite="pqc", mode="buffer")
    if pq:
        fig, ax = plt.subplots(figsize=(10, 6))
        labels, std, pqc = [], [], []
        for scheme in SCHEMES.values():
            for stdop, pqop, label in (
                ("encrypt", "encrypt_sign", "Encrypt"),
                ("decrypt", "decrypt_verify", "Decrypt"),
            ):
                a = rec.find(suite="core", scheme=scheme, mode="buffer", operation=stdop)
                b = rec.find(suite="pqc", scheme=scheme, mode="buffer", operation=pqop)
                if a and b:
                    labels.append(f"{scheme}\n{label}")
                    std.append(a[0].stats["median_ms"])
                    pqc.append(b[0].stats["median_ms"])
        x = list(range(len(labels)))
        ax.bar([i - 0.18 for i in x], std, 0.36, label="Standard")
        ax.bar([i + 0.18 for i in x], pqc, 0.36, label="ML-DSA Sign/Verify")
        ax.set_xticks(x, labels)
        ax.set_ylabel("Median latency (ms)")
        ax.set_title("Post-Quantum Signature Overhead - Buffer API")
        ax.legend()
        ax.grid(axis="y", alpha=0.2)
        fig.tight_layout()
        fig.savefig(charts / "03_pqc_overhead.png", dpi=220)
        plt.close(fig)

    rows = rec.find(suite="policy_scaling")
    if rows:
        fig, ax = plt.subplots(figsize=(10, 6))
        for scheme in SCHEMES.values():
            for op in ("encrypt", "decrypt"):
                sub = sorted(rec.find(suite="policy_scaling", scheme=scheme, operation=op), key=lambda r: r.policy_attributes)
                if sub:
                    ax.plot([r.policy_attributes for r in sub], [r.stats["median_ms"] for r in sub], marker="o", label=f"{scheme} {op}")
        ax.set_xlabel("Logical policy terms (CoverCrypt: bounded dimensions)")
        ax.set_ylabel("Median latency (ms)")
        ax.set_title("Policy Complexity Scaling")
        ax.legend()
        ax.grid(alpha=0.2)
        fig.tight_layout()
        fig.savefig(charts / "04_policy_scaling.png", dpi=220)
        plt.close(fig)

    rows = rec.find(suite="payload_scaling")
    if rows:
        fig, ax = plt.subplots(figsize=(11, 6))
        for scheme in SCHEMES.values():
            for variant, op in (("standard", "encrypt"), ("standard", "decrypt"), ("pqc", "encrypt_sign"), ("pqc", "decrypt_verify")):
                sub = sorted(rec.find(suite="payload_scaling", scheme=scheme, variant=variant, operation=op), key=lambda r: r.payload_bytes)
                if sub:
                    ax.plot([r.payload_bytes / 1024 for r in sub], [r.stats["median_ms"] for r in sub], marker="o", label=f"{scheme} {op}")
        ax.set_xscale("log", base=2)
        ax.set_xlabel("Payload size (KiB, log scale)")
        ax.set_ylabel("Median latency (ms)")
        ax.set_title("Payload Size Scaling")
        ax.legend(fontsize=8)
        ax.grid(alpha=0.2)
        fig.tight_layout()
        fig.savefig(charts / "05_payload_scaling.png", dpi=220)
        plt.close(fig)

    rows = rec.find(suite="mldsa")
    if rows:
        fig, ax = plt.subplots(figsize=(9, 5))
        for op in ("sign", "verify"):
            sub = sorted(rec.find(suite="mldsa", operation=op), key=lambda r: r.payload_bytes)
            ax.plot([r.payload_bytes / 1024 for r in sub], [r.stats["median_ms"] for r in sub], marker="o", label=op)
        ax.set_xscale("log", base=2)
        ax.set_xlabel("Message size (KiB, log scale)")
        ax.set_ylabel("Median latency (ms)")
        ax.set_title("ML-DSA-87 Sign / Verify")
        ax.legend()
        ax.grid(alpha=0.2)
        fig.tight_layout()
        fig.savefig(charts / "06_mldsa_latency.png", dpi=220)
        plt.close(fig)

    rows = rec.find(suite="aes_gcm")
    if rows:
        fig, ax = plt.subplots(figsize=(9, 5))
        for op in ("encrypt", "decrypt"):
            sub = sorted(rec.find(suite="aes_gcm", operation=op), key=lambda r: r.payload_bytes)
            ax.plot([r.payload_bytes / 1024 for r in sub], [r.extra["median_throughput_mib_s"] for r in sub], marker="o", label=op)
        ax.set_xscale("log", base=2)
        ax.set_xlabel("Payload size (KiB, log scale)")
        ax.set_ylabel("Throughput (MiB/s)")
        ax.set_title("AES-256-GCM Throughput")
        ax.legend()
        ax.grid(alpha=0.2)
        fig.tight_layout()
        fig.savefig(charts / "07_aes_gcm_throughput.png", dpi=220)
        plt.close(fig)
