# Hybrid PQ-CP-ABE Library
Hybrid Post-Quantum Ciphertext-Policy Attribute-Based Encryption Library for C/C++ in Windows/Linux


> [!NOTE]
> This library natively includes **Post-Quantum Cryptography (PQC)** integration using `liboqs` (specifically ML-DSA-87 signatures). It introduces a secure "Sign-then-Encrypt" architecture to prevent Surreptitious Forwarding attacks.

> [!IMPORTANT]
> **On the scope of "Post-Quantum" in this library:**
> The post-quantum (PQC) component only applies to the **digital signature layer** (ML-DSA-87, via `liboqs`), used to prevent Surreptitious Forwarding attacks in the "Sign-then-Encrypt" architecture.
>
> The **CP-ABE core (AC17/TKN20) remains classical**, based on pairing/discrete-log problems over elliptic curves — it is **not quantum-resistant**. In other words, this library is a **hybrid**: the attribute-based encryption (ABE) layer is still "classical," while only the signing/authentication layer is "post-quantum."
>
> Rationale: fully "native" post-quantum CP-ABE (e.g. lattice-based) is still an active area of **academic research**, with no published implementation that has reached a level of maturity or performance suitable for real-world use — most existing work remains at the **Proof-of-Concept (PoC)** stage or purely theoretical in papers, with no stable, runnable open-source code available. This library therefore takes a pragmatic approach: keep the well-established, high-performance classical CP-ABE core, and add a PQC signature layer on top to strengthen security in a way that's deployable today.

## Performance & Benchmarks

The library uses a **hybrid KEM/DEM-style architecture**: CP-ABE protects a randomly generated secret under the access policy, SHA3-256 derives the AES-256 key, and AES-GCM handles the bulk payload. The optional post-quantum path adds **ML-DSA-87 Sign-then-Encrypt** before the payload enters the hybrid encryption pipeline.

For the current binary format, AES-GCM authenticates the header as AAD:

`[Version | Scheme | IV | Encapsulated-Key Length | Encapsulated CP-ABE Key]`

The ML-DSA-87 layer signs:

`[PolicyLen | Policy | Plaintext]`

before encryption.

### Published Benchmark Snapshot

A reproducible benchmark snapshot is published under [`benchmark/published/2026-10-25_i5-12450HX_standard/`](benchmark/published/2026-10-25_i5-12450HX_standard/).

Benchmark environment:

- **CPU:** Intel Core i5-12450HX
- **Library:** v5.2.0
- **Profile:** Standard
- **Timed iterations:** 100 after 5 warm-up iterations
- **Payload:** 4 KiB
- **Policy:** 12 distinct attributes
- **Primary metric:** Median latency
- **Outlier policy:** No samples removed

| Implementation | Setup | KeyGen | Encrypt | Decrypt |
| --- | ---: | ---: | ---: | ---: |
| **AC17 Buffer** | 24.165 ms | 144.200 ms | 148.099 ms | **38.539 ms** |
| **TKN20 Buffer** | **14.710 ms** | 310.463 ms | **122.048 ms** | **30.654 ms** |
| **Charm-Crypto AC17** | 90.553 ms | 207.685 ms | 136.268 ms | 303.351 ms |

<p align="center">
  <img src="benchmark/published/2026-10-25_i5-12450HX_standard/charts/01_core_buffer_vs_charm.png" alt="AC17, TKN20 and Charm-Crypto AC17 benchmark" width="900"/>
</p>

The largest separation in this run appears in **decryption latency**: AC17 Buffer measured **38.539 ms**, TKN20 Buffer **30.654 ms**, and Charm-Crypto AC17 **303.351 ms**. TKN20 also produced the lowest setup and encryption medians in this test, while its KeyGen operation was the most expensive of the three.

### Post-Quantum Signature Cost

ML-DSA-87 primitive measurements for the same published run:

| Operation | Median |
| --- | ---: |
| KeyGen | 0.404 ms |
| Sign | 0.783 ms |
| Verify | 0.276 ms |

In the end-to-end Sign-then-Encrypt benchmark, the measured differences between the standard and ML-DSA-87 paths were smaller than the normal CP-ABE run-to-run variation. The primitive results are therefore the more useful signal for the actual cost of the post-quantum signature layer.

### Reproducibility

The published snapshot includes:

- [`report.md`](benchmark/published/2026-10-25_i5-12450HX_standard/report.md) — methodology, environment, results, and interpretation notes.
- [`summary.csv`](benchmark/published/2026-10-25_i5-12450HX_standard/summary.csv) — median, mean, p95, p99, standard deviation, and coefficient of variation.
- [`raw_samples.csv`](benchmark/published/2026-10-25_i5-12450HX_standard/raw_samples.csv) — every recorded timing sample.
- [`benchmark_results.json`](benchmark/published/2026-10-25_i5-12450HX_standard/benchmark_results.json) — machine-readable results and benchmark metadata.
- [`benchmark/`](benchmark/) — scripts and instructions required to reproduce the tests.

> [!IMPORTANT]
> **Benchmark comparison scope:** the native AC17/TKN20 measurements use the library's in-memory Buffer API and its byte-oriented hybrid pipeline. Charm-Crypto AC17 is also measured in memory, but its API operates directly on a GT group element. Charm is therefore included as a useful reference implementation rather than a strict end-to-end equivalent. The published results should not be interpreted as a universal speedup ratio across all workloads.

> [!NOTE]
> This library is specialized around **AC17** and **TKN20** CP-ABE with a native C/C++ integration surface. For projects that need a broader research-oriented collection of cryptographic schemes such as KP-ABE or IBE, [Charm-Crypto](https://github.com/JHUISI/charm) remains a broader framework.

## Building (Multi-OS)
> [!IMPORTANT]
> This library integrates the following cryptographic primitives and dependencies:
- [CryptoPP Library](https://github.com/weidai11/cryptopp)
- [CP-ABE AC17 Scheme](https://eprint.iacr.org/2017/807) (via [Rabe-ffi](https://github.com/WanThinnn/librabe-ffi.git))
- [CP-ABE TKN20 Scheme](https://eprint.iacr.org/2020/733) (via [Cloudflare CIRCL](https://github.com/cloudflare/circl/tree/main/abe))
- [Open Quantum Safe Library](https://github.com/open-quantum-safe/liboqs) (Open Quantum Safe - required for PQC Signatures)
- [HashiCorp Vault Secrets Engine](src/go/README.md) (Native Go plugin for Enterprise Cryptography-as-a-Service)

> [!NOTE]
>
> **Note on Dependencies:** All necessary dependencies (`CryptoPP`, `liboqs`, `rabe-ffi`, `circl`) have already been pre-compiled and included in the `src/cpp/lib/` folder for your convenience. You can build the main library immediately without installing anything else. However, if you wish to re-build these dependencies from source (e.g., for a different architecture), please read the instructions in [`src/cpp/lib/README.md`](file:///src/cpp/lib/README.md).

1. Clone the repository and navigate to the C++ source directory:
    ```sh
    git clone https://github.com/WanThinnn/Hybrid-PQ-CP-ABE-Library.git
    cd Hybrid-PQ-CP-ABE-Library
    cd src/cpp
    ```

### Option 1: Using Make (Recommended)
We provide a unified `Makefile` that automatically detects your operating system and compiler.

- **On Windows**: Open the **x64 Native Tools Command Prompt for VS 2022** (or equivalent) and run:
  ```cmd
  make clean
  make all
  make test
  ```
  *(Note: If you use MSYS2 or MinGW `make`, it works seamlessly as well!)*

- **On Linux / WSL**: Open your terminal and run:
  ```bash
  make clean
  make all
  make test
  ```

**Available Make Commands:**
- `make all`: Builds the static library, shared library, and executable.
- `make static`: Builds only the static library (`.lib` or `.a`).
- `make shared`: Builds only the shared library (`.dll` or `.so`).
- `make executable`: Builds only the CLI executable.
- `make test`: Runs the test suite. See `src/cpp/test/run_test.sh` or `src/cpp/test/run_test.bat` for more information.
- `make clean`: Removes all build artifacts and temporary files.

### Option 2: Using Visual Studio Code
The repository is also configured with a smart `tasks.json` for VS Code.

- **On Windows**: Open VS Code from the **x64 Native Tools Command Prompt for VS 2022**.
- **On Linux / WSL**: Open VS Code natively.
- Press `Ctrl+Shift+B` to run the configured build task.
- **Windows** will build using MSVC (`cl.exe`), and **Linux** will build using `g++`.
## Usage

### Using the Executable



The usage of the executable is as follows:
```sh
Usage: main [command] [--scheme <name>] [--pqc] [options]
Usage: main setup [--scheme <name>] <path_to_save_file>
Usage: main genkey [--scheme <name>] <master_key_file> <attributes> <private_key_file>
Usage: main encrypt [--scheme <name>] <public_key_file> [pqc_private_key] <plaintext_file> <policy> <ciphertext_file>
Usage: main decrypt <private_key_file> [pqc_public_key] <ciphertext_file> <recovertext_file>
```

Example commands (Standard Mode):
```sh
main setup --scheme tkn20 test_case
main genkey --scheme tkn20 "test_case/cpabe_msk.key" "A B C" "test_case/cpabe_sk.key"
main encrypt --scheme tkn20 "test_case/cpabe_pk.key" "test_case/plaintext.txt" "((A and C) or E)" "test_case/ciphertext.txt"
main decrypt "test_case/cpabe_sk.key" "test_case/ciphertext.txt" "test_case/recovertext.txt"
```

Example commands (Post-Quantum Mode):
```sh
main setup --scheme tkn20 --pqc test_case
main genkey --scheme tkn20 "test_case/cpabe_msk.key" "A B C" "test_case/cpabe_sk.key"
main encrypt --scheme tkn20 --pqc "test_case/cpabe_pk.key" "test_case/pqc_sk.key" "test_case/plaintext.txt" "\"A\"" "test_case/ciphertext.txt"
main decrypt --pqc "test_case/cpabe_sk.key" "test_case/pqc_pk.key" "test_case/ciphertext.txt" "test_case/recovertext.txt"
```
### Integrating the Library
After building the library, you can integrate it into any program on Windows/Linux. Here are the steps to include the library in your project.
Please go to <b>python-sources</b> folder to see more.

### HashiCorp Vault Plugin
This library natively provides a **HashiCorp Vault Custom Secrets Engine** written in Go (using Cgo to wrap the C++ core). It enables you to run a true "Cryptography-as-a-Service" architecture where the Master Secret Key (MSK) never leaves the Vault enclave.
- Exposes RESTful APIs: `/v1/abe/setup`, `/v1/abe/genkey`, `/v1/abe/encrypt`, `/v1/abe/decrypt`.
- Multi-stage Docker environments for seamless building and testing.
Please see the [**src/go/README.md**](src/go/README.md) and [**src/vault/README.md**](src/vault/README.md) for instructions on how to build, test, and deploy the plugin.

## Acknowledgements
Special thanks to [Aya0wind](https://github.com/Aya0wind) for the [Rabe-ffi](https://github.com/Aya0wind/Rabe-ffi) project, [Cloudflare](https://github.com/cloudflare/circl) for the Go-based CIRCL TKN20 implementation, [Open Quantum Safe](https://github.com/open-quantum-safe) for `liboqs`, and the [CryptoPP](https://github.com/weidai11/cryptopp) Library for helping me build this library.
## License

This project is open-source and available for anyone to use, modify, and distribute. We encourage you to clone, fork, and contribute to this project to help improve and expand its capabilities.
By contributing to this project, you agree that your contributions will be available under the same open terms.
