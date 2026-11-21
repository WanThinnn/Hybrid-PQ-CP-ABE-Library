"""Check real public Buffer encryption against an independent Boolean oracle."""
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'benchmark'))
from src.config import COVERCRYPT
from src.native import Native


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
        config = {'dimensions': [
            {'name': name, 'attributes': ['present', 'absent']} for name in 'ABCD'
        ] + [{'name': 'Extra', 'attributes': ['present']}]}
        native = Native(ROOT, config)
        backend = native.backend(COVERCRYPT)
        pk, msk = backend.setup()
        plaintext = b'Real ABE access-control regression\x00\xff'
        ciphertexts = [
            (node, backend.encrypt(pk, plaintext, expression(node)))
            for node in policies
        ]
        for bits in range(16):
            attributes = {name for index, name in enumerate('ABCD') if bits & (1 << index)}
            # Extra is a real unrelated attribute. The empty subset of
            # A/B/C/D must not gain access merely by owning Extra.
            grants = [name + '::present' for name in sorted(attributes)] + ['Extra::present']
            key = backend.keygen(msk, ' '.join(grants))
            for node, ciphertext in ciphertexts:
                with self.subTest(attributes=sorted(attributes), policy=expression(node)):
                    if satisfies(node, attributes):
                        self.assertEqual(backend.decrypt(key, ciphertext), plaintext)
                    else:
                        with self.assertRaisesRegex(RuntimeError, r'code: -3'):
                            backend.decrypt(key, ciphertext)


if __name__ == '__main__':
    unittest.main()
