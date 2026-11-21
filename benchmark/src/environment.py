from __future__ import annotations

import os
import platform
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

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
    system = platform.system()

    if system == "Windows":
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

    elif system == "Darwin":
        try:
            proc = subprocess.run(
                ["sysctl", "-n", "machdep.cpu.brand_string"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if proc.returncode == 0 and proc.stdout.strip():
                return proc.stdout.strip()
        except Exception:
            pass
        try:
            proc = subprocess.run(
                ["sysctl", "-n", "hw.model"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if proc.returncode == 0 and proc.stdout.strip():
                return proc.stdout.strip()
        except Exception:
            pass

    elif system == "Linux":
        try:
            cpuinfo = Path("/proc/cpuinfo")
            if cpuinfo.is_file():
                for line in cpuinfo.read_text(encoding="utf-8", errors="ignore").splitlines():
                    if ":" not in line:
                        continue
                    key, value = line.split(":", 1)
                    if key.strip().lower() in ("model name", "hardware") and value.strip():
                        return value.strip()
        except Exception:
            pass
        try:
            proc = subprocess.run(
                ["lscpu"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if proc.returncode == 0:
                for line in proc.stdout.splitlines():
                    if ":" not in line:
                        continue
                    key, value = line.split(":", 1)
                    if key.strip().lower() in ("model name", "model") and value.strip():
                        return value.strip()
        except Exception:
            pass

    cpu = os.environ.get("PROCESSOR_IDENTIFIER") or platform.processor()
    if cpu:
        return cpu.strip()

    return platform.machine() or "Unknown"


def published_cpu_slug(cpu: str) -> str:
    match = re.search(r"\b(i[3579]-\d+[A-Za-z0-9]*)\b", cpu, re.IGNORECASE)
    if match:
        return match.group(1)

    match = re.search(r"\b(Ryzen\s+\d+\s+\d+[A-Za-z0-9]*)\b", cpu, re.IGNORECASE)
    if match:
        return re.sub(r"\s+", "-", match.group(1))

    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", cpu).strip("-")
    return slug[:48] or "unknown-cpu"


def environment(native, root):
    cpu = detect_cpu_model()
    env = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "os": platform.platform(),
        "cpu": cpu,
        "architecture": platform.machine(),
        "logical_cpu_count": os.cpu_count(),
        "python": sys.version.replace("\n", " "),
        "library_version": native.version,
        "python_binding_version": native.binding_version,
        "library_path": native.path,
        "benchmark_api": "pq_cp_abe modern Python API (6.1)",
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
