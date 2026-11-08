# Unreleased — Vault authority integration

- Store large authorities as bounded immutable chunks with a final manifest
  commit, while retaining readers for original and retired CPQA storage formats.
  Interrupted or corrupt storage fails closed; reads never regenerate keys.
- Add read-only `authority` inspection, explicit `create_only` provisioning and
  fingerprint-bound public-key references to avoid oversized public-key requests.
  Small-key Base64 defaults and existing Base64 encrypt requests remain valid.
- Add optional explicit signing selection and encryption-time version metadata.
  Omitted signing selection retains the previous default. Native C ABI, key
  serialization, ciphertext format and third-party sources are unchanged.
- Add bounded-storage failure/corruption/compatibility tests and HTTP coverage
  for the six-dimension large-key case, including a disposable real Raft fixture.

See [authority contract and recovery](../plugins/vault/AUTHORITY.md) and
[test instructions](../plugins/vault/TESTING.md). This is source under development,
not a published release; `VERSION` remains unchanged until release preparation.
