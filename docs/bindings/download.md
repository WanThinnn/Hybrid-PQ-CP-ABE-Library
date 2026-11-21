---
title: Download
description: Download the prebuilt PQ-CP-ABE native SDK for Windows, Linux or macOS.
icon: lucide/download
---

# Download a prebuilt native SDK

For most users, downloading a prebuilt SDK is faster than building the native library from source.

## Choose your platform

Choose the package for your platform. These links point directly to the archive, so the download starts without opening the GitHub Releases page.

<div class="pq-download-grid" markdown>

[:lucide-download: **Windows x86-64**](https://github.com/WanThinnn/Hybrid-PQ-CP-ABE-Library/releases/download/v6.0.2/libhybrid-pq-cp-abe_win_x86_64_v6.0.2.zip){ .md-button .pq-download-button data-platform="windows" data-arch="x86_64" }

[:lucide-download: **Linux x86-64**](https://github.com/WanThinnn/Hybrid-PQ-CP-ABE-Library/releases/download/v6.0.2/libhybrid-pq-cp-abe_linux_x86_64_v6.0.2.zip){ .md-button .pq-download-button data-platform="linux" data-arch="x86_64" }

[:lucide-download: **macOS Apple Silicon**](https://github.com/WanThinnn/Hybrid-PQ-CP-ABE-Library/releases/download/v6.0.2/libhybrid-pq-cp-abe_macos12_arm64_v6.0.2.zip){ .md-button .pq-download-button data-platform="macos" data-arch="arm64" }

[:lucide-download: **macOS Intel**](https://github.com/WanThinnn/Hybrid-PQ-CP-ABE-Library/releases/download/v6.0.2/libhybrid-pq-cp-abe_macos12_x86_64_v6.0.2.zip){ .md-button .pq-download-button data-platform="macos" data-arch="x86_64" }

</div>

## Use the SDK

Extract the archive and use its `include/` directory for headers and `lib/` directory for linking. Keep the headers and native libraries from the **same release**.

!!! note
    These direct links target the release, `v6.0.2`. When a new release is published, the asset URLs must be updated because the version is part of each archive filename.

If a suitable prebuilt archive is not available for your OS or architecture, follow the [build-from-source guide](../native/build.md).
