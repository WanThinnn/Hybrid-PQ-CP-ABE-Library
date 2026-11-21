function fallbackPlatformDetection() {
  const ua = (navigator.userAgent || "").toLowerCase();
  const platform = (navigator.platform || "").toLowerCase();

  let os = "unknown";
  let arch = "unknown";

  if (ua.includes("windows") || platform.includes("win")) {
    os = "windows";
  } else if (ua.includes("mac") || platform.includes("mac")) {
    os = "macos";
  } else if (ua.includes("linux") || platform.includes("linux")) {
    os = "linux";
  }

  if (ua.includes("arm64") || ua.includes("aarch64")) {
    arch = "arm64";
  } else if (
    ua.includes("x86_64") ||
    ua.includes("amd64") ||
    ua.includes("win64") ||
    ua.includes("x64") ||
    platform.includes("x86_64") ||
    platform.includes("amd64") ||
    platform.includes("win64")
  ) {
    arch = "x86_64";
  }

  // Safari intentionally hides Apple Silicon vs Intel in many cases.
  // Prefer the current Apple Silicon build unless Intel is positively known.
  if (os === "macos" && arch === "unknown") {
    arch = "arm64";
  }

  return { os, arch };
}

async function detectDownloadPlatform() {
  const fallback = fallbackPlatformDetection();
  const uaData = navigator.userAgentData;

  if (!uaData || typeof uaData.getHighEntropyValues !== "function") {
    return fallback;
  }

  try {
    const info = await uaData.getHighEntropyValues(["platform", "architecture"]);
    const platform = (info.platform || "").toLowerCase();
    const architecture = (info.architecture || "").toLowerCase();

    let os = fallback.os;
    let arch = fallback.arch;

    if (platform.includes("windows")) os = "windows";
    else if (platform.includes("mac")) os = "macos";
    else if (platform.includes("linux")) os = "linux";

    if (architecture.includes("arm")) arch = "arm64";
    else if (
      architecture.includes("x86") ||
      architecture.includes("amd64") ||
      architecture.includes("x64")
    ) {
      arch = "x86_64";
    }

    return { os, arch };
  } catch {
    return fallback;
  }
}

const PQ_CP_ABE_RELEASE_API =
  "https://api.github.com/repos/WanThinnn/Hybrid-PQ-CP-ABE/releases/latest";

let latestReleasePromise;

function releaseAssetPatterns(platform, arch) {
  if (platform === "windows" && arch === "x86_64") {
    return [/^libhybrid-pq-cp-abe_win_x86_64_v[^/]+\.zip$/];
  }
  if (platform === "linux" && arch === "x86_64") {
    return [/^libhybrid-pq-cp-abe_linux_x86_64_v[^/]+\.zip$/];
  }
  if (platform === "macos" && arch === "arm64") {
    return [
      /^libhybrid-pq-cp-abe_macos12_arm64_v[^/]+\.zip$/,
      /^libhybrid-pq-cp-abe_macos_arm64_v[^/]+\.zip$/,
    ];
  }
  if (platform === "macos" && arch === "x86_64") {
    return [
      /^libhybrid-pq-cp-abe_macos12_x86_64_v[^/]+\.zip$/,
      /^libhybrid-pq-cp-abe_macos_x86_64_v[^/]+\.zip$/,
    ];
  }
  return [];
}

function findReleaseAsset(release, platform, arch) {
  const assets = Array.isArray(release?.assets) ? release.assets : [];
  for (const pattern of releaseAssetPatterns(platform, arch)) {
    const asset = assets.find((candidate) => pattern.test(candidate.name || ""));
    if (asset) return asset;
  }
  return null;
}

function fetchLatestStableRelease() {
  if (!latestReleasePromise) {
    latestReleasePromise = fetch(PQ_CP_ABE_RELEASE_API, {
      headers: { Accept: "application/vnd.github+json" },
    }).then((response) => {
      if (!response.ok) {
        throw new Error(`GitHub Releases API returned ${response.status}`);
      }
      return response.json();
    });
  }
  return latestReleasePromise;
}

function showReleaseVersion(button, version) {
  if (!version) return;
  let badge = button.querySelector(".pq-download-version");
  if (!badge) {
    badge = document.createElement("span");
    badge.className = "pq-download-version";
    button.appendChild(badge);
  }
  badge.textContent = ` · ${version}`;
}

async function resolveReleaseDownloads(buttons) {
  try {
    const release = await fetchLatestStableRelease();
    const version = release.tag_name || "";

    buttons.forEach((button) => {
      const asset = findReleaseAsset(
        release,
        button.dataset.platform,
        button.dataset.arch
      );
      if (!asset?.browser_download_url) return;

      button.href = asset.browser_download_url;
      button.dataset.releaseVersion = version;
      button.title = `Download ${asset.name}`;
      showReleaseVersion(button, version);
    });
  } catch (error) {
    console.warn("Could not resolve latest PQ-CP-ABE release assets:", error);
  }
}

async function applyDownloadRecommendation() {
  const buttons = Array.from(document.querySelectorAll(".pq-download-button"));
  if (!buttons.length) return;

  await resolveReleaseDownloads(buttons);

  buttons.forEach((button) => {
    button.classList.remove("md-button--primary");
    button.removeAttribute("data-recommended");
    button.removeAttribute("aria-current");
  });

  const { os, arch } = await detectDownloadPlatform();

  let match = buttons.find(
    (button) =>
      button.dataset.platform === os &&
      button.dataset.arch === arch
  );

  if (!match) {
    match = buttons.find((button) => button.dataset.platform === os);
  }

  if (!match) return;

  match.classList.add("md-button--primary");
  match.dataset.recommended = "true";
  match.setAttribute("aria-current", "true");
  match.title = `${match.title || "Download"} · Recommended for this device`;
}

function initDownloadRecommendation() {
  void applyDownloadRecommendation();
}

if (typeof document$ !== "undefined") {
  document$.subscribe(initDownloadRecommendation);
} else if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", initDownloadRecommendation, { once: true });
} else {
  initDownloadRecommendation();
}
