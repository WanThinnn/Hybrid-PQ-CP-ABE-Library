#!/usr/bin/env python3
"""
Comprehensive, reproducible benchmark suite for Hybrid PQ-CP-ABE Library.

Outputs:
- raw_samples.csv
- summary.csv
- benchmark_results.json
- report.md
- charts/*.png

The Charm-Crypto AC17 suite is a reference primitive only. It is not treated
as a strict apples-to-apples equivalent of the native byte-oriented hybrid
CP-ABE + SHA3-256 + AES-GCM pipeline.
"""

from __future__ import annotations

import argparse
import contextlib
import csv
import ctypes
import gc
import json
import math
import os
import platform
import random
import shutil
import statistics
import subprocess
import sys
import time
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional


AC17 = 0
TKN20 = 1
OK = 0
SCHEMES = {AC17: "AC17", TKN20: "TKN20"}

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


def human_bytes(n: int) -> str:
    value = float(n)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if value < 1024 or unit == "GiB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.2f} {unit}"
        value /= 1024
    return str(n)


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


def adaptive_iterations(base: int, size: int) -> int:
    if size >= 8388608:
        return min(base, 20)
    if size >= 1048576:
        return min(base, 50)
    if size >= 65536:
        return min(base, 100)
    return base


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
) -> tuple[list[float], Any]:
    last = None
    with silence_native(quiet):
        for _ in range(warmup):
            last = fn()
        gc.collect()
        gc_on = gc.isenabled()
        if gc_on:
            gc.disable()
        samples = []
        try:
            for _ in range(iterations):
                t0 = time.perf_counter_ns()
                last = fn()
                samples.append((time.perf_counter_ns() - t0) / 1_000_000.0)
        finally:
            if gc_on:
                gc.enable()
    return samples, last


@dataclass
class Record:
    benchmark_id: str
    suite: str
    scheme: str
    mode: str
    variant: str
    operation: str
    case: str
    payload_bytes: int
    policy_attributes: int
    stats: dict[str, float]
    extra: dict[str, Any]


class Recorder:
    def __init__(self):
        self.records: list[Record] = []
        self.raw: list[dict[str, Any]] = []

    def add(
        self,
        suite: str,
        scheme: str,
        mode: str,
        variant: str,
        operation: str,
        case: str,
        payload_bytes: int,
        policy_attributes: int,
        samples: list[float],
        extra: Optional[dict[str, Any]] = None,
    ):
        bid = "|".join((suite, scheme, mode, variant, operation, case))
        rec = Record(
            bid, suite, scheme, mode, variant, operation, case,
            payload_bytes, policy_attributes, stats(samples), extra or {}
        )
        self.records.append(rec)
        for i, value in enumerate(samples):
            self.raw.append({
                "benchmark_id": bid,
                "sample_index": i,
                "latency_ms": value,
            })

    def find(self, **filters):
        rows = self.records
        for key, value in filters.items():
            if value is not None:
                rows = [r for r in rows if getattr(r, key) == value]
        return rows

    def raw_for(self, bid):
        return [r["latency_ms"] for r in self.raw if r["benchmark_id"] == bid]


class Native:
    U8 = ctypes.c_ubyte
    P8 = ctypes.POINTER(U8)

    def __init__(self, path: Path):
        self.path = path.resolve()
        self._dll_handle = None
        if platform.system() == "Windows" and hasattr(os, "add_dll_directory"):
            self._dll_handle = os.add_dll_directory(str(self.path.parent))
        self.lib = ctypes.CDLL(str(self.path))
        self.bind()

    def bind(self):
        P8 = self.P8
        P = ctypes.POINTER
        S = ctypes.c_size_t
        I = ctypes.c_int
        C = ctypes.c_char_p

        self.lib.getVersion.argtypes = []
        self.lib.getVersion.restype = C
        self.lib.getErrorMessage.argtypes = [I]
        self.lib.getErrorMessage.restype = C
        self.lib.freeBuffer.argtypes = [P8]

        self.lib.setup_with_scheme.argtypes = [C, I]
        self.lib.generateSecretKey_with_scheme.argtypes = [C, C, C, I]
        self.lib.hybrid_cpabe_encrypt_with_scheme.argtypes = [C, C, C, C, I]
        self.lib.hybrid_cpabe_decrypt.argtypes = [C, C, C]

        self.lib.hybrid_cpabe_setup_with_pqc_scheme.argtypes = [C, I]
        self.lib.hybrid_cpabe_encrypt_and_sign_with_scheme.argtypes = [C, C, C, C, C, I]
        self.lib.hybrid_cpabe_decrypt_and_verify.argtypes = [C, C, C, C]

        self.lib.hybrid_cpabe_setupBuffer_with_scheme.argtypes = [
            P(P8), P(S), P(P8), P(S), I
        ]
        self.lib.hybrid_cpabe_setupBuffer_with_pqc_scheme.argtypes = [
            P(P8), P(S), P(P8), P(S), P(P8), P(S), P(P8), P(S), I
        ]
        self.lib.hybrid_cpabe_genkeyBuffer_with_scheme.argtypes = [
            P8, S, C, P(P8), P(S), I
        ]
        self.lib.hybrid_cpabe_encryptBuffer_with_scheme.argtypes = [
            P8, S, P8, S, C, P(P8), P(S), I
        ]
        self.lib.hybrid_cpabe_decryptBuffer.argtypes = [
            P8, S, P8, S, P(P8), P(S)
        ]
        self.lib.hybrid_cpabe_encryptBuffer_and_sign_with_scheme.argtypes = [
            P8, S, P8, S, P8, S, C, P(P8), P(S), I
        ]
        self.lib.hybrid_cpabe_decryptBuffer_and_verify.argtypes = [
            P8, S, P8, S, P8, S, P(P8), P(S)
        ]

        self.lib.ml_dsa_87_generate_keypair.argtypes = [P(P8), P(S), P(P8), P(S)]
        self.lib.ml_dsa_87_sign.argtypes = [P8, S, P8, P(P8), P(S)]
        self.lib.ml_dsa_87_verify.argtypes = [P8, S, P8, S, P8]

        self.lib.aes_gcm_encrypt.argtypes = [
            P8, S, P8, S, P8, S, P8, S, P(P8), P(S)
        ]
        self.lib.aes_gcm_decrypt.argtypes = [
            P8, S, P8, S, P8, S, P8, S, P(P8), P(S)
        ]

        for name in (
            "setup_with_scheme", "generateSecretKey_with_scheme",
            "hybrid_cpabe_encrypt_with_scheme", "hybrid_cpabe_decrypt",
            "hybrid_cpabe_setup_with_pqc_scheme",
            "hybrid_cpabe_encrypt_and_sign_with_scheme",
            "hybrid_cpabe_decrypt_and_verify",
            "hybrid_cpabe_setupBuffer_with_scheme",
            "hybrid_cpabe_setupBuffer_with_pqc_scheme",
            "hybrid_cpabe_genkeyBuffer_with_scheme",
            "hybrid_cpabe_encryptBuffer_with_scheme",
            "hybrid_cpabe_decryptBuffer",
            "hybrid_cpabe_encryptBuffer_and_sign_with_scheme",
            "hybrid_cpabe_decryptBuffer_and_verify",
            "ml_dsa_87_generate_keypair", "ml_dsa_87_sign", "ml_dsa_87_verify",
            "aes_gcm_encrypt", "aes_gcm_decrypt",
        ):
            getattr(self.lib, name).restype = I

    def version(self):
        raw = self.lib.getVersion()
        return raw.decode() if raw else "unknown"

    def check(self, code, name):
        if code != OK:
            msg = self.lib.getErrorMessage(code)
            detail = msg.decode(errors="replace") if msg else str(code)
            raise RuntimeError(f"{name}: {detail} ({code})")

    def arr(self, data: bytes):
        return (self.U8 * max(1, len(data))).from_buffer_copy(data or b"\x00")

    def take(self, ptr, length):
        try:
            return ctypes.string_at(ptr, length) if ptr and length else b""
        finally:
            if ptr:
                self.lib.freeBuffer(ptr)

    def p(self, path):
        return str(path).encode("utf-8")

    def setup_buffer(self, scheme):
        pk, msk = self.P8(), self.P8()
        pkl, mskl = ctypes.c_size_t(), ctypes.c_size_t()
        code = self.lib.hybrid_cpabe_setupBuffer_with_scheme(
            ctypes.byref(pk), ctypes.byref(pkl),
            ctypes.byref(msk), ctypes.byref(mskl), scheme
        )
        self.check(code, "setup_buffer")
        return self.take(pk, pkl.value), self.take(msk, mskl.value)

    def setup_pqc_buffer(self, scheme):
        ap, am, pp, ps = self.P8(), self.P8(), self.P8(), self.P8()
        apl, aml, ppl, psl = [ctypes.c_size_t() for _ in range(4)]
        code = self.lib.hybrid_cpabe_setupBuffer_with_pqc_scheme(
            ctypes.byref(ap), ctypes.byref(apl),
            ctypes.byref(am), ctypes.byref(aml),
            ctypes.byref(pp), ctypes.byref(ppl),
            ctypes.byref(ps), ctypes.byref(psl), scheme
        )
        self.check(code, "setup_pqc_buffer")
        return (
            self.take(ap, apl.value), self.take(am, aml.value),
            self.take(pp, ppl.value), self.take(ps, psl.value),
        )

    def genkey_buffer(self, msk, attrs, scheme):
        out, outl = self.P8(), ctypes.c_size_t()
        code = self.lib.hybrid_cpabe_genkeyBuffer_with_scheme(
            self.arr(msk), len(msk), attrs.encode(),
            ctypes.byref(out), ctypes.byref(outl), scheme
        )
        self.check(code, "genkey_buffer")
        return self.take(out, outl.value)

    def encrypt_buffer(self, pk, data, policy, scheme):
        out, outl = self.P8(), ctypes.c_size_t()
        code = self.lib.hybrid_cpabe_encryptBuffer_with_scheme(
            self.arr(pk), len(pk), self.arr(data), len(data), policy.encode(),
            ctypes.byref(out), ctypes.byref(outl), scheme
        )
        self.check(code, "encrypt_buffer")
        return self.take(out, outl.value)

    def decrypt_buffer(self, sk, ct):
        out, outl = self.P8(), ctypes.c_size_t()
        code = self.lib.hybrid_cpabe_decryptBuffer(
            self.arr(sk), len(sk), self.arr(ct), len(ct),
            ctypes.byref(out), ctypes.byref(outl)
        )
        self.check(code, "decrypt_buffer")
        return self.take(out, outl.value)

    def encrypt_pqc_buffer(self, pk, pqc_sk_b64, data, policy, scheme):
        out, outl = self.P8(), ctypes.c_size_t()
        code = self.lib.hybrid_cpabe_encryptBuffer_and_sign_with_scheme(
            self.arr(pk), len(pk), self.arr(pqc_sk_b64), len(pqc_sk_b64),
            self.arr(data), len(data), policy.encode(),
            ctypes.byref(out), ctypes.byref(outl), scheme
        )
        self.check(code, "encrypt_pqc_buffer")
        return self.take(out, outl.value)

    def decrypt_pqc_buffer(self, sk, pqc_pk_b64, ct):
        out, outl = self.P8(), ctypes.c_size_t()
        code = self.lib.hybrid_cpabe_decryptBuffer_and_verify(
            self.arr(sk), len(sk), self.arr(pqc_pk_b64), len(pqc_pk_b64),
            self.arr(ct), len(ct), ctypes.byref(out), ctypes.byref(outl)
        )
        self.check(code, "decrypt_pqc_buffer")
        return self.take(out, outl.value)

    def setup_file(self, d, scheme):
        self.check(self.lib.setup_with_scheme(self.p(d), scheme), "setup_file")

    def genkey_file(self, msk, attrs, sk, scheme):
        self.check(
            self.lib.generateSecretKey_with_scheme(
                self.p(msk), attrs.encode(), self.p(sk), scheme
            ), "genkey_file"
        )

    def encrypt_file(self, pk, pt, policy, ct, scheme):
        self.check(
            self.lib.hybrid_cpabe_encrypt_with_scheme(
                self.p(pk), self.p(pt), policy.encode(), self.p(ct), scheme
            ), "encrypt_file"
        )

    def decrypt_file(self, sk, ct, out):
        self.check(
            self.lib.hybrid_cpabe_decrypt(self.p(sk), self.p(ct), self.p(out)),
            "decrypt_file"
        )

    def ml_dsa_keypair(self):
        pk, sk = self.P8(), self.P8()
        pkl, skl = ctypes.c_size_t(), ctypes.c_size_t()
        self.check(
            self.lib.ml_dsa_87_generate_keypair(
                ctypes.byref(pk), ctypes.byref(pkl),
                ctypes.byref(sk), ctypes.byref(skl)
            ), "ml_dsa_keypair"
        )
        return self.take(pk, pkl.value), self.take(sk, skl.value)

    def ml_dsa_sign(self, msg, sk):
        sig, sigl = self.P8(), ctypes.c_size_t()
        self.check(
            self.lib.ml_dsa_87_sign(
                self.arr(msg), len(msg), self.arr(sk),
                ctypes.byref(sig), ctypes.byref(sigl)
            ), "ml_dsa_sign"
        )
        return self.take(sig, sigl.value)

    def ml_dsa_verify(self, msg, sig, pk):
        self.check(
            self.lib.ml_dsa_87_verify(
                self.arr(msg), len(msg), self.arr(sig), len(sig), self.arr(pk)
            ), "ml_dsa_verify"
        )

    def aes_encrypt(self, key, iv, pt, aad):
        out, outl = self.P8(), ctypes.c_size_t()
        self.check(
            self.lib.aes_gcm_encrypt(
                self.arr(key), len(key), self.arr(iv), len(iv),
                self.arr(pt), len(pt), self.arr(aad), len(aad),
                ctypes.byref(out), ctypes.byref(outl)
            ), "aes_encrypt"
        )
        return self.take(out, outl.value)

    def aes_decrypt(self, key, iv, ct, aad):
        out, outl = self.P8(), ctypes.c_size_t()
        self.check(
            self.lib.aes_gcm_decrypt(
                self.arr(key), len(key), self.arr(iv), len(iv),
                self.arr(ct), len(ct), self.arr(aad), len(aad),
                ctypes.byref(out), ctypes.byref(outl)
            ), "aes_decrypt"
        )
        return self.take(out, outl.value)


def lib_name():
    if platform.system() == "Windows":
        return "libhybrid-pq-cp-abe.dll"
    if platform.system() == "Darwin":
        return "libhybrid-pq-cp-abe.dylib"
    return "libhybrid-pq-cp-abe.so"


def repo_root(script: Path, explicit: Optional[str]):
    if explicit:
        return Path(explicit).expanduser().resolve()
    env = os.environ.get("HYBRID_CPABE_ROOT")
    if env:
        return Path(env).expanduser().resolve()
    candidate = script.parent.parent
    return candidate if (candidate / "src").exists() and (candidate / "Makefile").exists() else None


def find_lib(root: Optional[Path], explicit: Optional[str]):
    if explicit:
        path = Path(explicit).expanduser().resolve()
        if not path.exists():
            raise FileNotFoundError(path)
        return path
    candidates = []
    if root:
        name = lib_name()
        system = platform.system()
        platform_dir = "windows" if system == "Windows" else "macos" if system == "Darwin" else "linux"
        candidates = [
            root / "lib" / "dynamic" / name,
            root / "bindings" / "python" / "lib" / name,
            root / "build" / platform_dir / name,
        ]
    for path in candidates:
        if path.exists():
            return path.resolve()
    raise FileNotFoundError(
        "Native library not found. Use --lib PATH or --repo-root PATH. Checked: "
        + ", ".join(str(p) for p in candidates)
    )


def add(rec, samples, suite, scheme, mode, variant, op, case, payload, attrs, extra=None):
    rec.add(suite, scheme, mode, variant, op, case, payload, attrs, samples, extra)


def run_core_buffer(native, rec, scheme, payload, policy, attrs, policy_count, n, warm, quiet):
    name = SCHEMES[scheme]
    samples, pair = measure(lambda: native.setup_buffer(scheme), n, warm, quiet)
    add(rec, samples, "core", name, "buffer", "standard", "setup", "baseline", len(payload), policy_count)
    pk, msk = pair

    samples, sk = measure(lambda: native.genkey_buffer(msk, attrs, scheme), n, warm, quiet)
    add(rec, samples, "core", name, "buffer", "standard", "keygen", "baseline", len(payload), policy_count)

    samples, ct = measure(lambda: native.encrypt_buffer(pk, payload, policy, scheme), n, warm, quiet)
    add(rec, samples, "core", name, "buffer", "standard", "encrypt", "baseline", len(payload), policy_count, {"ciphertext_bytes": len(ct)})

    samples, pt = measure(lambda: native.decrypt_buffer(sk, ct), n, warm, quiet)
    if pt != payload:
        raise RuntimeError(f"{name} buffer correctness failed")
    add(rec, samples, "core", name, "buffer", "standard", "decrypt", "baseline", len(payload), policy_count)


def run_core_file(native, rec, scheme, payload, policy, attrs, policy_count, n, warm, quiet, tmp):
    name = SCHEMES[scheme]
    d = tmp / f"file_{name.lower()}"
    d.mkdir(parents=True, exist_ok=True)
    pt, sk, ct, out = d / "input.bin", d / "user.key", d / "ct.bin", d / "out.bin"
    pt.write_bytes(payload)

    samples, _ = measure(lambda: native.setup_file(d, scheme), n, warm, quiet)
    add(rec, samples, "core", name, "file", "standard", "setup", "baseline", len(payload), policy_count)

    msk, pk = d / "cpabe_msk.key", d / "cpabe_pk.key"
    samples, _ = measure(lambda: native.genkey_file(msk, attrs, sk, scheme), n, warm, quiet)
    add(rec, samples, "core", name, "file", "standard", "keygen", "baseline", len(payload), policy_count)

    samples, _ = measure(lambda: native.encrypt_file(pk, pt, policy, ct, scheme), n, warm, quiet)
    add(rec, samples, "core", name, "file", "standard", "encrypt", "baseline", len(payload), policy_count, {"ciphertext_bytes": ct.stat().st_size})

    samples, _ = measure(lambda: native.decrypt_file(sk, ct, out), n, warm, quiet)
    if out.read_bytes() != payload:
        raise RuntimeError(f"{name} file correctness failed")
    add(rec, samples, "core", name, "file", "standard", "decrypt", "baseline", len(payload), policy_count)


def run_pqc_buffer(native, rec, scheme, payload, policy, attrs, policy_count, n, warm, quiet):
    name = SCHEMES[scheme]
    samples, setup = measure(lambda: native.setup_pqc_buffer(scheme), n, warm, quiet)
    add(rec, samples, "pqc", name, "buffer", "pqc", "setup_pqc", "baseline", len(payload), policy_count)
    pk, msk, pq_pk, pq_sk = setup
    user_sk = native.genkey_buffer(msk, attrs, scheme)

    samples, ct = measure(lambda: native.encrypt_pqc_buffer(pk, pq_sk, payload, policy, scheme), n, warm, quiet)
    add(rec, samples, "pqc", name, "buffer", "pqc", "encrypt_sign", "baseline", len(payload), policy_count, {"ciphertext_bytes": len(ct)})

    samples, pt = measure(lambda: native.decrypt_pqc_buffer(user_sk, pq_pk, ct), n, warm, quiet)
    if pt != payload:
        raise RuntimeError(f"{name} PQC correctness failed")
    add(rec, samples, "pqc", name, "buffer", "pqc", "decrypt_verify", "baseline", len(payload), policy_count)


def run_mldsa(native, rec, sizes, base, warm, quiet):
    samples, pair = measure(native.ml_dsa_keypair, base, warm, quiet)
    pk, sk = pair
    add(rec, samples, "mldsa", "ML-DSA-87", "native", "primitive", "keygen", "keypair", 0, 0, {"pk_bytes": len(pk), "sk_bytes": len(sk)})
    for size in sizes:
        n = adaptive_iterations(base, size)
        msg = os.urandom(size)
        samples, sig = measure(lambda: native.ml_dsa_sign(msg, sk), n, warm, quiet)
        add(rec, samples, "mldsa", "ML-DSA-87", "native", "primitive", "sign", human_bytes(size), size, 0, {"signature_bytes": len(sig)})
        native.ml_dsa_verify(msg, sig, pk)
        samples, _ = measure(lambda: native.ml_dsa_verify(msg, sig, pk), n, warm, quiet)
        add(rec, samples, "mldsa", "ML-DSA-87", "native", "primitive", "verify", human_bytes(size), size, 0)


def run_aes(native, rec, sizes, base, warm, quiet):
    key, iv, aad = os.urandom(32), os.urandom(12), os.urandom(64)
    for size in sizes:
        n = adaptive_iterations(base, size)
        pt = os.urandom(size)
        samples, ct = measure(lambda: native.aes_encrypt(key, iv, pt, aad), n, warm, quiet)
        med = statistics.median(samples)
        thr = (size / 1048576) / (med / 1000) if med else 0
        add(rec, samples, "aes_gcm", "AES-256-GCM", "native", "primitive", "encrypt", human_bytes(size), size, 0, {"median_throughput_mib_s": thr})
        if native.aes_decrypt(key, iv, ct, aad) != pt:
            raise RuntimeError("AES-GCM correctness failed")
        samples, _ = measure(lambda: native.aes_decrypt(key, iv, ct, aad), n, warm, quiet)
        med = statistics.median(samples)
        thr = (size / 1048576) / (med / 1000) if med else 0
        add(rec, samples, "aes_gcm", "AES-256-GCM", "native", "primitive", "decrypt", human_bytes(size), size, 0, {"median_throughput_mib_s": thr})


def run_policy_scaling(native, rec, sizes, n, warm, quiet):
    payload = os.urandom(4096)
    for scheme in (AC17, TKN20):
        name = SCHEMES[scheme]
        pk, msk = native.setup_buffer(scheme)
        for count in sizes:
            policy, attrs = policy_for(count), attrs_for(count)
            sk = native.genkey_buffer(msk, attrs, scheme)
            samples, ct = measure(lambda p=policy: native.encrypt_buffer(pk, payload, p, scheme), n, warm, quiet)
            add(rec, samples, "policy_scaling", name, "buffer", "standard", "encrypt", f"{count} attrs", len(payload), count)
            samples, pt = measure(lambda c=ct: native.decrypt_buffer(sk, c), n, warm, quiet)
            if pt != payload:
                raise RuntimeError(f"{name} policy scaling failed at {count}")
            add(rec, samples, "policy_scaling", name, "buffer", "standard", "decrypt", f"{count} attrs", len(payload), count)


def run_payload_scaling(native, rec, sizes, base, warm, quiet, policy_count, with_pqc):
    policy, attrs = policy_for(policy_count), attrs_for(policy_count)
    for scheme in (AC17, TKN20):
        name = SCHEMES[scheme]
        pk, msk = native.setup_buffer(scheme)
        sk = native.genkey_buffer(msk, attrs, scheme)
        if with_pqc:
            ppk, pmsk, pq_pk, pq_sk = native.setup_pqc_buffer(scheme)
            puser = native.genkey_buffer(pmsk, attrs, scheme)
        for size in sizes:
            n = adaptive_iterations(base, size)
            payload = os.urandom(size)
            samples, ct = measure(lambda d=payload: native.encrypt_buffer(pk, d, policy, scheme), n, warm, quiet)
            add(rec, samples, "payload_scaling", name, "buffer", "standard", "encrypt", human_bytes(size), size, policy_count)
            samples, pt = measure(lambda c=ct: native.decrypt_buffer(sk, c), n, warm, quiet)
            if pt != payload:
                raise RuntimeError(f"{name} payload scaling failed")
            add(rec, samples, "payload_scaling", name, "buffer", "standard", "decrypt", human_bytes(size), size, policy_count)
            if with_pqc:
                samples, pct = measure(lambda d=payload: native.encrypt_pqc_buffer(ppk, pq_sk, d, policy, scheme), n, warm, quiet)
                add(rec, samples, "payload_scaling", name, "buffer", "pqc", "encrypt_sign", human_bytes(size), size, policy_count)
                samples, ppt = measure(lambda c=pct: native.decrypt_pqc_buffer(puser, pq_pk, c), n, warm, quiet)
                if ppt != payload:
                    raise RuntimeError(f"{name} PQC payload scaling failed")
                add(rec, samples, "payload_scaling", name, "buffer", "pqc", "decrypt_verify", human_bytes(size), size, policy_count)


def run_charm(rec, n, warm, policy, count):
    try:
        from charm.toolbox.pairinggroup import PairingGroup, GT
        from charm.schemes.abenc.ac17 import AC17CPABE
    except Exception as exc:
        print(f"Charm-Crypto unavailable, skipped: {exc}")
        return False
    group = PairingGroup("BN254")
    ac17 = AC17CPABE(group_obj=group, assump_size=2)
    attrs = attrs_for(count).split()

    samples, pair = measure(ac17.setup, n, warm, False)
    add(rec, samples, "charm_reference", "AC17", "python", "primitive_reference", "setup", "baseline", 0, count)
    pk, msk = pair
    samples, sk = measure(lambda: ac17.keygen(pk, msk, attrs), n, warm, False)
    add(rec, samples, "charm_reference", "AC17", "python", "primitive_reference", "keygen", "baseline", 0, count)
    msg = group.random(GT)
    samples, ct = measure(lambda: ac17.encrypt(pk, msg, policy), n, warm, False)
    add(rec, samples, "charm_reference", "AC17", "python", "primitive_reference", "encrypt", "GT element", 0, count)
    samples, out = measure(lambda: ac17.decrypt(pk, ct, sk), n, warm, False)
    if out != msg:
        raise RuntimeError("Charm correctness failed")
    add(rec, samples, "charm_reference", "AC17", "python", "primitive_reference", "decrypt", "GT element", 0, count)
    return True


def git_info(root):
    result = {"commit": None, "dirty": None}
    if not root:
        return result
    try:
        p = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, capture_output=True, text=True, timeout=5)
        if p.returncode == 0:
            result["commit"] = p.stdout.strip()
        p = subprocess.run(["git", "status", "--porcelain"], cwd=root, capture_output=True, text=True, timeout=5)
        if p.returncode == 0:
            result["dirty"] = bool(p.stdout.strip())
    except Exception:
        pass
    return result


def detect_cpu_model():
    cpu = os.environ.get("PROCESSOR_IDENTIFIER") or platform.processor()
    if cpu:
        return cpu.strip()

    if platform.system() == "Windows":
        try:
            proc = subprocess.run(
                [
                    "powershell", "-NoProfile", "-NonInteractive", "-Command",
                    "(Get-CimInstance Win32_Processor | Select-Object -First 1 -ExpandProperty Name)"
                ],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if proc.returncode == 0 and proc.stdout.strip():
                return proc.stdout.strip()
        except Exception:
            pass

    return platform.machine() or "Unknown"


def environment(native, root):
    cpu = detect_cpu_model()
    env = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "os": platform.platform(),
        "cpu": cpu,
        "architecture": platform.machine(),
        "logical_cpu_count": os.cpu_count(),
        "python": sys.version.replace("\n", " "),
        "library_version": native.version(),
    }
    try:
        import psutil
        mem = psutil.virtual_memory()
        freq = psutil.cpu_freq()
        env.update({
            "physical_cpu_count": psutil.cpu_count(logical=False),
            "memory_total_bytes": mem.total,
            "cpu_freq_current_mhz": freq.current if freq else None,
            "cpu_load_percent_at_start": psutil.cpu_percent(interval=0.2),
        })
    except Exception:
        env["psutil"] = "not installed"
    env.update({f"git_{k}": v for k, v in git_info(root).items()})
    return env


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


def matplotlib_module():
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    return plt


def make_charts(rec, out):
    plt = matplotlib_module()
    charts = out / "charts"
    charts.mkdir(exist_ok=True)

    core = rec.find(suite="core")
    if core:
        fig, ax = plt.subplots(figsize=(12, 6))
        ops = ["setup", "keygen", "encrypt", "decrypt"]
        series = [("AC17", "file"), ("AC17", "buffer"), ("TKN20", "file"), ("TKN20", "buffer")]
        x = list(range(4))
        width = 0.18
        for idx, (scheme, mode) in enumerate(series):
            vals = []
            for op in ops:
                rows = rec.find(suite="core", scheme=scheme, mode=mode, operation=op)
                vals.append(rows[0].stats["median_ms"] if rows else 0)
            offset = (idx - 1.5) * width
            ax.bar([v + offset for v in x], vals, width, label=f"{scheme} {mode}")
        ax.set_xticks(x, ["Setup", "KeyGen", "Encrypt", "Decrypt"])
        ax.set_ylabel("Median latency (ms)")
        ax.set_title("Native CP-ABE Core Performance")
        ax.legend()
        ax.grid(axis="y", alpha=0.2)
        fig.tight_layout()
        fig.savefig(charts / "01_core_latency.png", dpi=220)
        plt.close(fig)

        fig, ax = plt.subplots(figsize=(9, 6))
        groups, labels = [], []
        for scheme, mode in series:
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
        for scheme in ("AC17", "TKN20"):
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
        for scheme in ("AC17", "TKN20"):
            for op in ("encrypt", "decrypt"):
                sub = sorted(rec.find(suite="policy_scaling", scheme=scheme, operation=op), key=lambda r: r.policy_attributes)
                ax.plot([r.policy_attributes for r in sub], [r.stats["median_ms"] for r in sub], marker="o", label=f"{scheme} {op}")
        ax.set_xlabel("Distinct attributes in AND policy")
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
        for scheme in ("AC17", "TKN20"):
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
    for scheme in ("AC17", "TKN20"):
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
        f"| Git commit | {env.get('git_commit') or 'n/a'} |",
        f"| Git dirty | {env.get('git_dirty')} |",
    ])

    text = f"""# Hybrid PQ-CP-ABE Performance Benchmark Report

Generated: {env.get('timestamp_utc')}

## Executive summary

This run measures native AC17/TKN20 performance, File I/O versus Buffer APIs,
ML-DSA-87 Sign-then-Encrypt overhead, ML-DSA and AES-GCM primitives, policy
complexity scaling, and payload-size scaling.

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
- Every benchmark family performs a correctness check.
- Baseline policy contains exactly {config['policy_attributes']} distinct
  attributes; generated scaling labels therefore match the actual policy.
- Baseline payload: {human_bytes(config['payload_bytes'])}.

## Charm-Crypto reference

{"Charm-Crypto AC17 was available." if charm else "Charm-Crypto was unavailable and skipped."}

Charm-Crypto is reported as a primitive reference, not as an apples-to-apples
end-to-end equivalent. Charm AC17 encrypts a GT group element. The native
library exposes a byte-oriented hybrid path that protects a random secret,
derives an AES key, and encrypts data with AES-GCM. Universal speedup claims
must not be inferred directly from this comparison.

## Environment

{env_table}

## Configuration

{json.dumps(config, indent=2)}

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

## Charm reference

{table(rec.find(suite="charm_reference"))}

## Charts

![Core latency](charts/01_core_latency.png)

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
6. AC17/TKN20 remain classical pairing/discrete-log cryptography. The
   post-quantum component measured here is ML-DSA-87 signatures.
"""
    (out / "report.md").write_text(text, encoding="utf-8")


def args():
    p = argparse.ArgumentParser(description="Hybrid PQ-CP-ABE comprehensive benchmark")
    p.add_argument("--profile", choices=PROFILES, default="standard")
    p.add_argument("--repo-root")
    p.add_argument("--lib")
    p.add_argument("--output")
    p.add_argument("--iterations", type=int)
    p.add_argument("--warmup", type=int)
    p.add_argument("--payload-bytes", type=int, default=4096)
    p.add_argument("--policy-attributes", type=int, default=12)
    p.add_argument("--seed", type=int, default=2026)
    p.add_argument("--no-file", action="store_true")
    p.add_argument("--no-pqc", action="store_true")
    p.add_argument("--no-micro", action="store_true")
    p.add_argument("--no-scaling", action="store_true")
    p.add_argument("--no-charm", action="store_true")
    p.add_argument("--quiet-native", action=argparse.BooleanOptionalAction, default=True)
    return p.parse_args()


def main():
    a = args()
    profile = dict(PROFILES[a.profile])
    if a.iterations is not None:
        profile["iterations"] = a.iterations
    if a.warmup is not None:
        profile["warmup"] = a.warmup
    if a.policy_attributes < 1 or a.payload_bytes < 1:
        raise ValueError("policy attributes and payload bytes must be positive")

    script = Path(__file__).resolve()
    root = repo_root(script, a.repo_root)
    path = find_lib(root, a.lib)
    native = Native(path)

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    if a.output:
        out = Path(a.output).expanduser().resolve()
    elif root:
        out = root / "benchmark" / "results" / f"run_{stamp}"
    else:
        out = script.parent / "results" / f"run_{stamp}"
    out.mkdir(parents=True, exist_ok=True)
    tmp = out / "_tmp"
    tmp.mkdir(exist_ok=True)

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
        "include_file": not a.no_file,
        "include_pqc": not a.no_pqc,
        "include_micro": not a.no_micro,
        "include_scaling": not a.no_scaling,
        "include_charm": not a.no_charm,
        "library_path": str(path),
        "repo_root": str(root) if root else None,
    }
    env = environment(native, root)
    rec = Recorder()

    print("=" * 70)
    print("Hybrid PQ-CP-ABE Comprehensive Benchmark")
    print("=" * 70)
    print(f"Library: {path}")
    print(f"Version: {native.version()}")
    print(f"Profile: {a.profile}")
    print(f"Output:  {out}")

    schemes = [AC17, TKN20]
    random.Random(a.seed).shuffle(schemes)

    try:
        print("[1/5] Native core")
        for scheme in schemes:
            run_core_buffer(native, rec, scheme, payload, policy, attrs, a.policy_attributes, profile["iterations"], profile["warmup"], a.quiet_native)
            if not a.no_file:
                run_core_file(native, rec, scheme, payload, policy, attrs, a.policy_attributes, profile["iterations"], profile["warmup"], a.quiet_native, tmp)

        print("[2/5] PQC Sign-then-Encrypt")
        if not a.no_pqc:
            for scheme in schemes:
                run_pqc_buffer(native, rec, scheme, payload, policy, attrs, a.policy_attributes, profile["iterations"], profile["warmup"], a.quiet_native)

        print("[3/5] Primitive microbenchmarks")
        if not a.no_micro:
            if not a.no_pqc:
                run_mldsa(native, rec, profile["micro_sizes"], profile["micro_iterations"], profile["warmup"], a.quiet_native)
            run_aes(native, rec, profile["micro_sizes"], profile["micro_iterations"], profile["warmup"], a.quiet_native)

        print("[4/5] Scaling")
        if not a.no_scaling:
            run_policy_scaling(native, rec, profile["policy_sizes"], profile["scale_iterations"], profile["warmup"], a.quiet_native)
            run_payload_scaling(native, rec, profile["payload_sizes"], profile["scale_iterations"], profile["warmup"], a.quiet_native, a.policy_attributes, not a.no_pqc)

        print("[5/5] Charm reference + outputs")
        charm = False if a.no_charm else run_charm(rec, profile["iterations"], profile["warmup"], policy, a.policy_attributes)

        write_data(rec, out, env, config)
        make_charts(rec, out)
        report(rec, out, env, config, charm)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print("Done.")
    print(f"Report: {out / 'report.md'}")
    print(f"Raw:    {out / 'raw_samples.csv'}")
    print(f"Charts: {out / 'charts'}")


if __name__ == "__main__":
    main()
