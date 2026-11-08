# Vault authority storage, public keys and recovery

This contract is implemented in `vault-plugin-abe/plugin/`; it does not change
the native C ABI, key serialization, cryptographic primitives or ciphertext
envelope. It applies to AC17, TKN20 and CoverCrypt mounts independently.

## Public API contract version 1

`PUT <mount>/setup` accepts the existing `scheme`, `pqc`, `config_json` and
`mode` fields plus:

| Field | Default | Meaning |
| --- | --- | --- |
| `create_only` | `false` | Reject any active authority or partial legacy authority state before generating keys when true. |
| `public_key_format` | `auto` | `auto`, `base64` or `reference`; affects only public transport, never key bytes. |

The historical default still **replaces** the authority. New provisioning
clients should use `create_only=true`. Never retry setup to recover a lost
response or missing application KV record. Concurrent requests on the active
backend select at most one create-only initializer. Vault ACLs must restrict
setup and growth to operators; encrypt permission does not grant either.

`GET <mount>/authority` reads public metadata without changing storage. Its
optional query parameter `public_key_format` uses the same values. It returns
404 when no readable active/legacy authority exists; storage corruption is an
error, never a fallback to old master keys. A 404 does not justify clearing
application initialization guards: partial legacy state or unpublished chunks
may still exist. A legacy authority without a saved public key cannot have
that key reconstructed through this endpoint.

Public responses include `contract_version: 1`, `public_key`,
`public_key_format`, `public_key_fingerprint`, `scheme`, `revision`, `pqc`,
`native_version`, and applicable `config_json`, `mode`, `pqc_public_key` fields.
JSON configuration text is compacted consistently on setup and later reads;
clients should compare parsed dimension/configuration semantics.
Fingerprint is lowercase SHA-256 over the **raw public-key bytes**. It identifies
a public key; it is not a secret, user credential or proof of authorization.
Revision starts at 1 on setup and increases on growth, so use fingerprint and
revision together, never revision alone across authority replacements.

| Requested transport | Returned `public_key_format` | `public_key` |
| --- | --- | --- |
| `base64` | `base64` | Original Base64 key bytes. Explicit export can be very large. |
| `reference` | `vault-authority-sha256-v1` | `vault-authority-sha256:<64 lowercase hex digits>` |
| `auto` | Either above | Base64 for raw keys up to 256 KiB, reference above that threshold. |

`PUT <mount>/encrypt` accepts either representation in its existing
`public_key` field. A reference must exactly match the stored public key **and**
requested scheme on that mount; malformed, stale, cross-scheme and different-key
references fail before native encryption. Native crypto always receives the
actual original key bytes. Existing Base64 requests remain supported. A client
can retain small-key Base64 behavior or request references consistently.

`add_dimension` keeps its existing request contract and uses `auto` for the
updated public response. Growth changes the public key/fingerprint. Retain old
version metadata and keys; a new reference does not convert old ciphertexts.

### Signatures and new-ciphertext metadata

`encrypt` accepts optional `sign`:

| Request | Behavior |
| --- | --- |
| Omitted | Preserve the historical authority/explicit signing-key default. |
| `true` | Sign using the explicit `pqc_private_key` or stored signing key; fail if neither exists. |
| `false` | Encrypt without a signature, even when the authority has a signing key. An explicit private key conflicts and is rejected. |

The response retains `ciphertext` and adds `crypto_metadata` for the encryption
that just succeeded:

```json
{
  "schema": 1,
  "scheme": "covercrypt",
  "backend": "vault",
  "format": "hybrid-v2",
  "pqc_signed": true,
  "keyset_id": "<raw-public-key-sha256>",
  "authority_revision": 1
}
```

`authority_revision` is supplied only when the encryption key matches the
stored authority's key and scheme. `keyset_id` is the actual encryption key's
fingerprint, including for an explicit external Base64 key. `hybrid-v2` is the
existing native envelope shared by all three schemes; its scheme tag is
checked against the request before success. No ciphertext format is changed.

Persist this metadata with the new ciphertext version over the authenticated
Vault connection. It is an encryption-time response, **not** a parser or proof
of signature mode for arbitrary historical ciphertext. Unknown historical
signature/keyset state must not be guessed from current configuration. Signed
decrypt requests must still supply the correct verifier; metadata alone does
not perform signature verification. Vault decrypt's existing contract remains
unchanged. The optional signing layer is ML-DSA-87, separate from CoverCrypt's
hybridized/post-quantum KEM mode.

## Storage and compatibility

Vault Raft defaults to a 1-MiB maximum entry. HTTP request limits are separate;
raising the listener limit does not fix an oversized stored authority. See
[HashiCorp Raft configuration](https://developer.hashicorp.com/vault/docs/configuration/storage/raft)
and [TCP listener configuration](https://developer.hashicorp.com/vault/docs/configuration/listener/tcp).

The plugin keeps the logical commit point at `msk/authority`:

- A small serialized authority (up to 192 KiB) remains a format-1 JSON record.
- A larger authority uses a format-3 manifest plus immutable 192-KiB raw chunks
  at `msk/authority/chunks/<random-generation>/<index>`. All are under the
  existing `msk/` seal-wrap prefix. The conservative chunk budget leaves room
  for transport/barrier overhead and 512-KiB backend limits.
- The manifest commits only after every chunk write succeeds. It records
  revision, generation, chunk size/count, total size and SHA-256. Reads validate
  bounds, exact chunk lengths, checksum and payload revision before use.
- The serialized payload is limited to 1 GiB by this plugin. This is a resource
  budget, not a guarantee that all configurations fit a deployment's memory,
  latency or timeout budget. Large authorities still require substantial RAM
  and storage I/O; references reduce HTTP/KV traffic, not native key size.

The reader also supports the original single-record format 1, legacy
`msk/abe`/`msk/pqc`/`config/abe` layouts, and the retired CPQA format-2 manifest
(768-KiB chunks, no `chunk_size` field). The 87-character retired reference
encoding has the same exact raw-key fingerprint semantics. Compatibility reads
do not rewrite or regenerate keys. The next successful authority growth writes
the current storage format while preserving the existing cryptographic keys.
Unknown or corrupt primary formats fail closed without using legacy state.

Old and interrupted generations are retained intentionally. A reader may have
already loaded an older manifest; deleting its chunks would break it. A storage
timeout may also mean the manifest actually committed. Do not delete chunks on
that error path. There is no automatic garbage-collection endpoint in this
change; account for retained generations in storage capacity planning.

## Operator recovery and upgrade

1. Back up the **complete** Vault storage using its supported snapshot/backup
   mechanism, including every authority chunk and existing user/signing keys.
   Retain the previous matched plugin/native binary pair for rollback.
2. Build/test the library and plugin together, register the executable checksum
   and reload through the deployment's normal procedure. Give the application
   `read` on `<mount>/authority`; keep operator write permissions separate.
3. Read `authority`, request reference transport when appropriate, and verify
   scheme, dimensions/config, KEM mode, public fingerprint, revision and signing
   state against the deployment's recorded intent. Reconcile application KV
   only after these checks. Do not export an MSK or signing secret.
4. If metadata is absent, corrupt or mismatched, stop recovery. Restore a known
   consistent backup or investigate with the operator. Do not run setup,
   recreate a mount, clear initialization guards or replace a master key.
5. Verify an existing ciphertext and user key, plus a denied user, before new
   writes. Keep per-version backend/scheme/key identity and signing metadata.

Rollback from format-3 writes to an old plugin requires restoring the matching
pre-upgrade storage snapshot; old plugins do not understand format 3. This
guide does not authorize a live reset or automatic key rotation. Adding a
dimension preserves existing rights; revocation/rotation is a separate
operation requiring explicit key/ciphertext lifecycle planning.
