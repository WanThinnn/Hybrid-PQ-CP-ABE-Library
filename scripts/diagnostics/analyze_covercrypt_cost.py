"""Bounded native CoverCrypt cost probe; key material is never written or logged."""
import json
import os
from pathlib import Path
import statistics
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]


def child(dimensions, values, mode):
    sys.path.insert(0, str(ROOT / 'bindings' / 'python'))
    from pq_cp_abe import CoverCryptABE, KemMode, AbeError
    with tempfile.TemporaryDirectory() as directory:
        config = Path(directory) / 'covercrypt.json'
        config.write_text(json.dumps({'dimensions': [
            {'name': f'D{i}', 'attributes': ['present', 'absent'][:values]}
            for i in range(dimensions)
        ]}), encoding='utf-8')
        os.environ['HCPABE_COVERCRYPT_CONFIG'] = str(config)
        os.environ['HCPABE_COVERCRYPT_MODE'] = mode
        native = CoverCryptABE(config=config.read_text(encoding='utf-8'),
                              mode={'classic': KemMode.CLASSIC, 'hybridized': KemMode.HYBRIDIZED}[mode])
        samples = []
        for _ in range(3):
            start = time.perf_counter()
            pk, msk = native.setup()
            samples.append((time.perf_counter() - start) * 1000)
        attrs = ' '.join(f'D{i}::present' for i in range(dimensions))
        policy = ' && '.join(f'D{i}::present' for i in range(dimensions))
        start = time.perf_counter()
        sk = native.keygen(msk, attrs)
        keygen_ms = (time.perf_counter() - start) * 1000
        payload = b'covercrypt-cost-probe'
        start = time.perf_counter()
        ct = native.encrypt(pk, payload, policy)
        encrypt_ms = (time.perf_counter() - start) * 1000
        assert native.decrypt(sk, ct) == payload
        missing = native.keygen(msk, ' '.join(attrs.split()[:-1]))
        try:
            native.decrypt(missing, ct)
        except AbeError:
            denied = True
        else:
            denied = False
        wrong_attribute_denied = None
        if values == 2:
            wrong_attrs = ' '.join(attrs.split()[:-1] + [f'D{dimensions-1}::absent'])
            wrong = native.keygen(msk, wrong_attrs)
            try:
                native.decrypt(wrong, ct)
            except AbeError:
                wrong_attribute_denied = True
            else:
                wrong_attribute_denied = False
        return dict(dimensions=dimensions, values=values, rights=(values+1)**dimensions,
                    mode=mode, setup_median_ms=statistics.median(samples),
                    keygen_ms=keygen_ms, encrypt_ms=encrypt_ms,
                    pk_bytes=len(pk), msk_bytes=len(msk), roundtrip=True,
                    omitted_dimension_denied=denied, wrong_attribute_denied=wrong_attribute_denied)


if __name__ == '__main__':
    if len(sys.argv) > 1:
        print(json.dumps(child(int(sys.argv[1]), int(sys.argv[2]), sys.argv[3])))
    else:
        results = []
        for dimensions, values in [(2, 2), (4, 2), (6, 2), (8, 2), (12, 1)]:
            for mode in ('classic', 'hybridized'):
                try:
                    run = subprocess.run([sys.executable, __file__, str(dimensions), str(values), mode],
                                         capture_output=True, text=True, timeout=20, check=True)
                    result = json.loads(run.stdout.strip().splitlines()[-1])
                except subprocess.TimeoutExpired:
                    result = dict(dimensions=dimensions, values=values, mode=mode, timeout_seconds=20)
                results.append(result)
                print(json.dumps(result), flush=True)
        output = ROOT / 'build/reports/covercrypt/covercrypt-cost-analysis.json'
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(results, indent=2))
