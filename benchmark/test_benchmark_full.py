"""Native regression checks for CoverCrypt benchmark configuration.

Run with: python -m unittest discover -s benchmark -p test_benchmark_full.py
Each native run is isolated and bounded so an exponential setup regression
fails the test instead of hanging the test runner.
"""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import benchmark_full as bench


ROOT = Path(__file__).resolve().parents[1]


class CovercryptBenchmarkTests(unittest.TestCase):
    def test_chart_series_uses_only_present_records(self):
        rows = [
            bench.Record(
                "core|AC17|buffer|standard|setup|baseline",
                "core", "AC17", "buffer", "standard", "setup", "baseline",
                4096, 12, {"median_ms": 10.0}, {},
            ),
            bench.Record(
                "core|CoverCrypt|buffer|standard|setup|baseline",
                "core", "CoverCrypt", "buffer", "standard", "setup", "baseline",
                4096, 12, {"median_ms": 2.0}, {},
            ),
        ]
        preferred = [
            "AC17 file", "AC17 buffer",
            "TKN20 file", "TKN20 buffer",
            "CoverCrypt file", "CoverCrypt buffer",
        ]
        data, series = bench._chart_series_data(
            rows, preferred, lambda row: f"{row.scheme} {row.mode}"
        )
        self.assertEqual(series, ["AC17 buffer", "CoverCrypt buffer"])
        self.assertEqual(data["AC17 buffer"]["setup"], 10.0)
        self.assertEqual(data["CoverCrypt buffer"]["setup"], 2.0)
        self.assertNotIn("AC17 file", data)
        self.assertNotIn("TKN20 buffer", data)

    def test_policy_terms_fit_bounded_configuration(self):
        with tempfile.TemporaryDirectory() as directory:
            old_config = os.environ.get("HCPABE_COVERCRYPT_CONFIG")
            old_mode = os.environ.get("HCPABE_COVERCRYPT_MODE")
            try:
                for profile in bench.PROFILES.values():
                    maximum = max(12, *profile["policy_sizes"])
                    config = json.loads(bench.configure_covercrypt(Path(directory), maximum).read_text())
                    dimensions = config["dimensions"]
                    self.assertEqual(len(dimensions), min(4, maximum))
                    qualified = {
                        f"{d['name']}::{attribute}"
                        for d in dimensions for attribute in d["attributes"]
                    }
                    self.assertEqual(len(qualified), maximum)
                    for count in profile["policy_sizes"]:
                        policy, attributes = bench.covercrypt_policy_attrs(count)
                        terms = set(bench.re.findall(r"BENCH_D\d+::V\d+", policy))
                        self.assertEqual(len(terms), count)
                        self.assertTrue(terms <= qualified)
                        self.assertTrue(set(attributes.split()) <= terms)
            finally:
                for name, value in (("HCPABE_COVERCRYPT_CONFIG", old_config),
                                    ("HCPABE_COVERCRYPT_MODE", old_mode)):
                    if value is None:
                        os.environ.pop(name, None)
                    else:
                        os.environ[name] = value

    def test_standard_and_full_showcase_complete_covercrypt_roundtrips(self):
        try:
            library = bench.find_lib(ROOT, None)
        except FileNotFoundError as error:
            self.skipTest(str(error))
        worker = """
import sys
sys.path.insert(0, sys.argv.pop(1))
import benchmark_full as bench
bench.NATIVE_SCHEMES = (bench.COVERCRYPT,)
bench.main()
"""
        for profile in ("standard", "full"):
            with self.subTest(profile=profile), tempfile.TemporaryDirectory() as directory:
                completed = subprocess.run(
                    [sys.executable, "-u", "-c", worker, str(ROOT / "benchmark"),
                     "--profile", profile, "--showcase", "--iterations", "2",
                     "--warmup", "1", "--no-micro", "--no-charm", "--no-primitive",
                     "--lib", str(library), "--output", directory],
                    cwd=ROOT, capture_output=True, text=True, timeout=30,
                )
                self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
                result = json.loads((Path(directory) / "benchmark_results.json").read_text())
                self.assertEqual(len(result["config"]["covercrypt_dimensions"]), 4)
                self.assertEqual(result["config"]["covercrypt_rights_universe_estimate"], 256)
                self.assertTrue((Path(directory) / "covercrypt_config.json").is_file())
                self.assertTrue((Path(directory) / "charts" / "01_core_latency.png").is_file())
                self.assertTrue((Path(directory) / "charts" / "01_core_latency_log.png").is_file())
                records = result["records"]
                self.assertEqual(len(records), 7)
                self.assertTrue(all(record["scheme"] == "CoverCrypt" for record in records))
                self.assertEqual(
                    {record["operation"] for record in records},
                    {"setup", "keygen", "encrypt", "decrypt", "setup_pqc",
                     "encrypt_sign", "decrypt_verify"},
                )
                self.assertTrue(all(record["stats"]["count"] == 2 for record in records))


if __name__ == "__main__":
    unittest.main()
