---
title: About
icon: lucide/info
---

# About

## The project

**Hybrid PQ-CP-ABE Library** is an open-source SDK for encrypting data under
attribute-based access policies. It brings AC17, TKN20 and CoverCrypt behind a
shared native interface, with Python and JavaScript / WebAssembly bindings, a
command-line tool and a HashiCorp Vault integration.

The library combines policy-based key protection with AES-GCM for payload
encryption. CoverCrypt supports classical, post-quantum and hybridized key
encapsulation; its hybridized mode combines Curve25519 with ML-KEM-768.
Optional ML-DSA signatures add authenticity to the encrypt/decrypt workflow.
AC17 and TKN20 remain classical ABE schemes, independently of the signature layer.

The project focuses on making these cryptographic operations practical to
integrate into applications: issuing attribute-bound user keys, enforcing
ciphertext policies and protecting data across native and browser environments.
Published benchmarks retain raw samples and document the workload and comparison
scope so readers can assess the measurements.

[Explore the architecture](../architecture/README.md) ·
[View benchmarks](../architecture/benchmarks.md) ·
[Browse the source](https://github.com/WanThinnn/Hybrid-PQ-CP-ABE-Library)

Learn about [the author](author.md) and the security projects behind
this work.

## Releases

See [Releases](../project/releases.md) for the existing release and packaging
workflow, or [GitHub Releases](https://github.com/WanThinnn/Hybrid-PQ-CP-ABE-Library/releases)
for published SDK assets.
