"""Compare persisted and ephemeral key generation in the same shared binary."""
import ctypes as c
import json
from pathlib import Path
import statistics
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tests'))
from test_covercrypt_shared import Buffer, SharedCovercryptTests

SharedCovercryptTests.setUpClass()
lib = SharedCovercryptTests.lib
config = json.dumps({'dimensions': [
    {'name': f'D{i}', 'attributes': ['present', 'absent']} for i in range(8)
]}).encode()
policy = ' && '.join(f'D{i}::present' for i in range(8)).encode()
msk, mpk = Buffer(), Buffer()
assert lib.cc_setup(config, 2, c.byref(msk), c.byref(mpk)) == 0
samples = {'persisted': [], 'ephemeral': []}
try:
    for iteration in range(12):
        order = ('persisted', 'ephemeral') if iteration % 2 == 0 else ('ephemeral', 'persisted')
        for method in order:
            updated, user = Buffer(), Buffer()
            start = time.perf_counter_ns()
            try:
                if method == 'persisted':
                    status = lib.cc_genkey(msk.data, msk.len, policy, c.byref(updated), c.byref(user))
                else:
                    status = lib.cc_genkey_ephemeral(msk.data, msk.len, policy, c.byref(user))
                assert status == 0
            finally:
                lib.cc_buffer_free(c.byref(user))
                lib.cc_buffer_free(c.byref(updated))
            elapsed = (time.perf_counter_ns() - start) / 1_000_000
            if iteration >= 2:
                samples[method].append(elapsed)
    medians = {name: statistics.median(values) for name, values in samples.items()}
    result = {'mode': 'hybridized', 'dimensions': 8, 'values_per_dimension': 2,
              'median_ms': medians, 'samples_ms': samples,
              'reduction_percent': 100 * (1 - medians['ephemeral'] / medians['persisted'])}
    output = ROOT / 'build/reports/covercrypt/covercrypt-genkey-comparison.json'
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2))
    print(json.dumps(result))
finally:
    lib.cc_buffer_free(c.byref(msk))
    lib.cc_buffer_free(c.byref(mpk))
