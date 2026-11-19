"""Wheel configuration for a ctypes package with bundled native libraries.

The Python API is interpreter-independent, but its shared libraries are NOT
platform-independent. Never emit py3-none-any for this package.
"""

import os
import platform
import shutil
import subprocess
from pathlib import Path

from setuptools.command.build_py import build_py
from setuptools import Distribution, setup
from setuptools.errors import SetupError
from wheel.bdist_wheel import bdist_wheel
from wheel.macosx_libfile import calculate_macosx_platform_tag

PACKAGE = Path(__file__).resolve().parent / "pq_cp_abe" / "_libs"
EXTENSIONS = {"Windows": "dll", "Linux": "so", "Darwin": "dylib"}


class PlatformDistribution(Distribution):
    def has_ext_modules(self):
        # Flag native contents so wheel uses platlib and a platform-specific tag.
        return True


class CleanBuildPy(build_py):
    def run(self):
        super().run()
        # Do not ship source-tree bytecode from local compileall/test runs.
        for cache in Path(self.build_lib).rglob("__pycache__"):
            if cache.is_dir():
                shutil.rmtree(cache)


class PlatformWheel(bdist_wheel):
    def run(self):
        extension = EXTENSIONS.get(platform.system())
        if not extension:
            raise SetupError(f"Unsupported Python wheel platform: {platform.system()}")
        core = PACKAGE / f"libhybrid-pq-cp-abe.{extension}"
        required = [core]
        if extension == "dll":
            required.append(PACKAGE / "libcpabe_tkn20.dll")
        for artifact in required:
            if not artifact.is_file() or artifact.stat().st_size == 0:
                raise SetupError(
                    f"Cannot build runnable wheel: missing {artifact}. "
                    "Run bindings/python/stage_native.py first."
                )
        super().run()

    def get_tag(self):
        # ctypes does not use the CPython extension-module ABI, so the Python
        # and ABI tags can be py3-none; the platform tag MUST remain native.
        _python_tag, _abi_tag, platform_tag = super().get_tag()
        if platform_tag == "any":
            raise SetupError("Refusing to package native binaries as a universal wheel")
        if platform.system() == "Darwin":
            # python.org CPython can report universal2 even when our bundled
            # release dylib has exactly one architecture. A universal2 tag
            # falsely promises both slices and causes delocate to fail.
            arch = os.environ.get("PQ_CP_ABE_WHEEL_ARCH", platform.machine()).lower()
            arch = {"amd64": "x86_64", "aarch64": "arm64"}.get(arch, arch)
            if arch not in ("x86_64", "arm64"):
                raise SetupError(f"Unsupported macOS wheel architecture: {arch}")
            dylib = PACKAGE / "libhybrid-pq-cp-abe.dylib"
            slices = subprocess.check_output(["lipo", "-archs", str(dylib)], text=True).split()
            if arch not in slices:
                raise SetupError(f"Native dylib lacks host architecture {arch}: {slices}")
            if len(slices) != 1:
                raise SetupError(f"Expected single-arch macOS dylib, found: {slices}")
            # Derive the minimum macOS deployment target from the actual
            # Mach-O files bundled in the package. The interpreter's platform
            # tag only supplies a floor; wheel.macosx_libfile raises it when
            # the dylib requires a newer macOS version.
            parts = platform_tag.split("_")
            if len(parts) < 4 or parts[0] != "macosx":
                raise SetupError(f"Unexpected macOS platform tag: {platform_tag}")
            base_major, base_minor = parts[1], parts[2]
            platform_tag = calculate_macosx_platform_tag(
                PACKAGE, f"macosx-{base_major}.{base_minor}-{arch}"
            )
        return "py3", "none", platform_tag


ROOT_VERSION = Path(__file__).resolve().parents[2] / "VERSION"
if not ROOT_VERSION.is_file():
    raise SetupError(f"Missing repository VERSION file: {ROOT_VERSION}")
VERSION = ROOT_VERSION.read_text(encoding="utf-8").strip()
if not VERSION:
    raise SetupError("Repository VERSION file cannot be empty")

setup(
    version=VERSION,
    distclass=PlatformDistribution,
    cmdclass={"build_py": CleanBuildPy, "bdist_wheel": PlatformWheel},
)
