"""Pure configuration and reporting tests. Never load native code or run timings."""

import json
import os
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

import re
from src import config as bench
from src.records import Record
from src.charts import _chart_series_data
from src.records import Recorder
from src import suites, reports


def fake_measure(fn, *_args):
    """Exercise mocked API wiring once; never call a clock or native code."""
    return [1.0, 2.0], fn()


class CovercryptBenchmarkTests(unittest.TestCase):
    def test_chart_series_uses_only_present_records(self):
        rows = [
            Record(
                "core|AC17|buffer|standard|setup|baseline",
                "core", "AC17", "buffer", "standard", "setup", "baseline",
                4096, 12, {"median_ms": 10.0}, {},
            ),
            Record(
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
        data, series = _chart_series_data(
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
                        terms = set(re.findall(r"BENCH_D\d+::V\d+", policy))
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

    @patch.object(suites, "measure", side_effect=fake_measure)
    def test_modern_comparison_api_and_correctness(self, _measure):
        for scheme in bench.NATIVE_SCHEMES:
            with self.subTest(scheme=scheme):
                backend = Mock()
                backend.setup.return_value = (b"public", b"master")
                backend.keygen.return_value = b"user"
                backend.encrypt.return_value = b"ciphertext"
                native = SimpleNamespace(backend=Mock(return_value=backend), api=Mock())
                secret = bytes(range(32))
                native.api.decrypt.return_value = secret
                rec = Recorder()
                suites.run_native_comparison(native, rec, scheme, "A", "A", 1, 2, 0, False)
                backend.keygen.assert_called_once_with(b"master", "A")
                backend.encrypt.assert_called_once_with(b"public", secret, "A")
                native.api.decrypt.assert_called_once_with(b"user", b"ciphertext")
                self.assertEqual(len(rec.records), 4)
                self.assertTrue(all(r.variant == "hybrid_32_bytes" for r in rec.records))
                native.api.decrypt.return_value = b"wrong"
                with self.assertRaisesRegex(RuntimeError, "correctness failed"):
                    suites.run_native_comparison(native, Recorder(), scheme, "A", "A", 1, 2, 0, False)

    @patch.object(suites, "measure", side_effect=fake_measure)
    def test_signing_api_uses_combined_keys_in_correct_order(self, _measure):
        backend = Mock()
        backend.setup_with_signing.return_value = (b"public", b"master", b"verify", b"sign")
        backend.keygen.return_value = b"user"
        backend.encrypt_and_sign.return_value = b"ciphertext"
        native = SimpleNamespace(backend=Mock(return_value=backend), api=Mock())
        native.api.decrypt_and_verify.return_value = b"payload"
        rec = Recorder()
        suites.run_pqc_buffer(native, rec, bench.COVERCRYPT, b"payload", "A", "A", 1, 2, 0, False)
        backend.encrypt_and_sign.assert_called_once_with(b"public", b"sign", b"payload", "A")
        native.api.decrypt_and_verify.assert_called_once_with(b"user", b"verify", b"ciphertext")
        self.assertEqual({r.operation for r in rec.records}, {"setup_pqc", "encrypt_sign", "decrypt_verify"})

    @patch.object(suites, "measure", side_effect=fake_measure)
    def test_invalid_signature_prevents_publication(self, _measure):
        signer = Mock()
        signer.generate_keypair.return_value = (b"public", b"secret")
        signer.sign.return_value = b"signature"
        signer.verify.return_value = False
        with self.assertRaisesRegex(RuntimeError, "signature correctness failed"):
            suites.run_mldsa(SimpleNamespace(signer=signer), Recorder(), [32], 2, 0, False)

    def test_report_exports_synthetic_samples_without_missing_chart_links(self):
        rec = Recorder()
        rec.add("primitive_compare", "AC17", "native", "hybrid_32_bytes", "protect",
                "32-byte key material", 32, 12, [1.0, 2.0, 100.0])
        config = {
            "profile": "quick", "iterations": 3, "warmup": 0, "payload_bytes": 32,
            "policy_attributes": 12, "covercrypt_dimension_count_effective": 4,
            "covercrypt_dimension_count_requested": 4, "seed": 2026,
        }
        env = {"library_version": "6.1.0", "python_binding_version": "6.1.0"}
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            reports.write_data(rec, out, env, config)
            reports.report(rec, out, env, config, False)
            reports.write_snapshot_readme(out, env, config, False)
            data = json.loads((out / "benchmark_results.json").read_text(encoding="utf-8"))
            self.assertEqual(data["records"][0]["stats"]["count"], 3)
            self.assertEqual(len((out / "raw_samples.csv").read_text().splitlines()), 4)
            report = (out / "report.md").read_text(encoding="utf-8")
            self.assertIn("modern Python hybrid API", report)
            self.assertIn("## Configuration\n\n```json\n", report)
            self.assertNotIn("![", report)
            readme = (out / "README.md").read_text(encoding="utf-8")
            self.assertIn("python main.py", readme)
            self.assertNotIn("benchmark_full.py", readme)



if __name__ == "__main__":
    unittest.main()
