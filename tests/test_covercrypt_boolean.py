"""Check real public Buffer encryption against an independent Boolean oracle."""
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'benchmark'))
from benchmark_full import COVERCRYPT, Native, find_lib


def expression(node):
    if isinstance(node, str):
        return node + '::present'
    operator, left, right = node
    return f'({expression(left)} {operator} {expression(right)})'


def satisfies(node, attributes):
    if isinstance(node, str):
        return node in attributes
    operator, left, right = node
    if operator == '&&':
        return satisfies(left, attributes) and satisfies(right, attributes)
    return satisfies(left, attributes) or satisfies(right, attributes)


class CovercryptBooleanTests(unittest.TestCase):
    def test_all_attribute_subsets_against_nested_and_or_policies(self):
        try:
            library = find_lib(ROOT, None)
        except FileNotFoundError as error:
            self.skipTest(str(error))
        policies = [
            'A', 'B', 'C', 'D',
            ('&&', 'A', 'B'), ('||', 'A', 'B'),
            ('&&', 'A', ('||', 'B', 'C')),
            ('||', ('&&', 'A', 'B'), ('&&', 'C', 'D')),
            ('&&', ('||', 'A', 'B'), ('||', 'C', 'D')),
            ('&&', ('&&', 'A', 'B'), ('&&', 'C', 'D')),
            ('||', ('||', 'A', 'B'), ('||', 'C', 'D')),
            ('||', ('&&', 'A', ('||', 'B', 'C')), 'D'),
            ('&&', 'A', ('||', 'B', ('&&', 'C', 'D'))),
            ('||', ('&&', 'A', 'B'), ('&&', 'A', 'C')),
        ]
        original = {name: os.environ.get(name) for name in ('HCPABE_COVERCRYPT_CONFIG', 'HCPABE_COVERCRYPT_MODE')}
        try:
            with tempfile.TemporaryDirectory() as directory:
                config = Path(directory) / 'policy.json'
                config.write_text(json.dumps({'dimensions': [
                    {'name': name, 'attributes': ['present', 'absent']} for name in 'ABCD'
                ] + [{'name': 'Extra', 'attributes': ['present']}]}))
                os.environ['HCPABE_COVERCRYPT_CONFIG'] = str(config)
                os.environ['HCPABE_COVERCRYPT_MODE'] = 'hybridized'
                native = Native(library)
                pk, msk = native.setup_buffer(COVERCRYPT)
                plaintext = b'Real ABE access-control regression\x00\xff'
                ciphertexts = [(node, native.encrypt_buffer(pk, plaintext, expression(node), COVERCRYPT))
                               for node in policies]
                for bits in range(16):
                    attributes = {name for index, name in enumerate('ABCD') if bits & (1 << index)}
                    # Extra is a real unrelated attribute. The empty subset of
                    # A/B/C/D must not gain access merely by owning Extra.
                    grants = [name + '::present' for name in sorted(attributes)] + ['Extra::present']
                    key = native.genkey_buffer(msk, ' '.join(grants), COVERCRYPT)
                    for node, ciphertext in ciphertexts:
                        with self.subTest(attributes=sorted(attributes), policy=expression(node)):
                            if satisfies(node, attributes):
                                self.assertEqual(native.decrypt_buffer(key, ciphertext), plaintext)
                            else:
                                with self.assertRaisesRegex(RuntimeError, r'\(-3\)'):
                                    native.decrypt_buffer(key, ciphertext)
        finally:
            for name, value in original.items():
                if value is None:
                    os.environ.pop(name, None)
                else:
                    os.environ[name] = value


if __name__ == '__main__':
    unittest.main()
