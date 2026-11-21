from __future__ import annotations

import contextlib
import gc
import math
import os
import statistics
import sys
import time
from typing import Any, Callable, Optional

def percentile(values: list[float], q: float) -> float:
    if not values:
        return float("nan")
    if len(values) == 1:
        return values[0]
    data = sorted(values)
    pos = (len(data) - 1) * q
    lo, hi = math.floor(pos), math.ceil(pos)
    if lo == hi:
        return data[lo]
    frac = pos - lo
    return data[lo] * (1.0 - frac) + data[hi] * frac


def stats(samples: list[float]) -> dict[str, float]:
    mean = statistics.fmean(samples)
    stdev = statistics.stdev(samples) if len(samples) > 1 else 0.0
    ci = 1.96 * stdev / math.sqrt(len(samples)) if len(samples) > 1 else 0.0
    return {
        "count": len(samples),
        "min_ms": min(samples),
        "mean_ms": mean,
        "median_ms": statistics.median(samples),
        "p95_ms": percentile(samples, 0.95),
        "p99_ms": percentile(samples, 0.99),
        "max_ms": max(samples),
        "stdev_ms": stdev,
        "cv_percent": (stdev / mean * 100.0) if mean else 0.0,
        "mean_ci95_low_ms": mean - ci,
        "mean_ci95_high_ms": mean + ci,
    }


@contextlib.contextmanager
def silence_native(enabled: bool):
    if not enabled:
        yield
        return
    try:
        sys.stdout.flush()
        sys.stderr.flush()
        out_fd, err_fd = sys.stdout.fileno(), sys.stderr.fileno()
        save_out, save_err = os.dup(out_fd), os.dup(err_fd)
        null_fd = os.open(os.devnull, os.O_WRONLY)
    except Exception:
        yield
        return
    try:
        os.dup2(null_fd, out_fd)
        os.dup2(null_fd, err_fd)
        yield
    finally:
        os.dup2(save_out, out_fd)
        os.dup2(save_err, err_fd)
        os.close(save_out)
        os.close(save_err)
        os.close(null_fd)


def measure(
    fn: Callable[[], Any],
    iterations: int,
    warmup: int,
    quiet: bool,
    label: Optional[str] = None,
) -> tuple[list[float], Any]:
    """Time only the API call, excluding log suppression and progress output."""
    if iterations < 1 or warmup < 0:
        raise ValueError("iterations must be positive and warmup nonnegative")
    if label:
        print(f"    -> {label} ({warmup} warmup, {iterations} timed)", flush=True)
    last = None
    samples = []
    with silence_native(quiet):
        for _ in range(warmup):
            last = fn()
        gc.collect()
        gc_on = gc.isenabled()
        if gc_on:
            gc.disable()
        try:
            for _ in range(iterations):
                start = time.perf_counter_ns()
                last = fn()
                elapsed_ms = (time.perf_counter_ns() - start) / 1_000_000.0
                samples.append(elapsed_ms)
        finally:
            if gc_on:
                gc.enable()
    if label:
        print(f"       done: median {statistics.median(samples):.3f} ms", flush=True)
    return samples, last
