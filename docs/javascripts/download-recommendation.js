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

async function applyDownloadRecommendation() {
  const buttons = Array.from(document.querySelectorAll(".pq-download-button"));
  if (!buttons.length) return;

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
  match.title = "Recommended for this device";
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
