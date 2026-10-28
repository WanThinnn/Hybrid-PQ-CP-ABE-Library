#!/usr/bin/env bash
# Tag a committed release; GitHub Actions builds all native platform packages.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

usage() {
    echo "Usage: ./scripts/release.sh <version> [--dry-run]"
    echo "Example: ./scripts/release.sh 5.2.1"
    echo "GitHub Actions builds Windows, Linux, macOS Intel and macOS Apple Silicon."
}

VERSION=""
DRY_RUN=false
for arg in "$@"; do
    case "$arg" in
        --dry-run) DRY_RUN=true ;;
        --help|-h) usage; exit 0 ;;
        --*) echo "Unknown option: $arg. Releases always build all platforms." >&2; usage; exit 2 ;;
        *)
            if [[ -n "$VERSION" ]]; then usage; exit 2; fi
            VERSION="${arg#v}"
            ;;
    esac
done
if ! [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]]; then
    echo "A version such as 5.2.1 or 5.2.1-rc1 is required." >&2
    usage
    exit 2
fi
TAG="v$VERSION"

echo "=== Hybrid CP-ABE Library Release Script ==="
echo "Version: $VERSION"
echo "Tag: $TAG"
echo "Platforms:"
echo "  - Windows (x86_64, MSVC)"
echo "  - Linux (x86_64)"
echo "  - macOS Intel (x86_64)"
echo "  - macOS Apple Silicon (arm64)"
echo
echo "Release assets (after every CI build and test passes):"
for platform in win_x86_64 linux_x86_64 macos_x86_64 macos_arm64; do
    echo "  - libhybrid-pq-cp-abe_${platform}_${TAG}.zip"
done
echo "  - SHA256SUMS.txt"
echo
if [[ "$DRY_RUN" == true ]]; then
    echo "Dry run: no files, commits, tags, or remotes were changed."
    exit 0
fi

# Release the committed tree, including the workflow and its supporting scripts.
if [[ -n "$(git status --porcelain)" ]]; then
    echo "Commit or stash working-tree changes before releasing." >&2
    exit 1
fi
FILE_VERSION="$(tr -d '\r\n' < VERSION)"
API_VERSION="$(sed -n 's/.*LIB_VERSION = "\([^"]*\)";.*/\1/p' include/hybrid_pq_cp_abe/hybrid-pq-cp-abe.h)"
if [[ "$FILE_VERSION" != "$VERSION" || "$API_VERSION" != "$VERSION" ]]; then
    echo "Update and commit VERSION and LIB_VERSION to $VERSION before releasing." >&2
    exit 1
fi
if [[ ! -f "release_notes/$TAG.md" ]]; then
    echo "Missing release notes: release_notes/$TAG.md" >&2
    exit 1
fi
if git rev-parse --verify --quiet "refs/tags/$TAG" >/dev/null; then
    echo "Local tag $TAG already exists; refusing to replace it." >&2
    exit 1
fi
if ! REMOTE_TAG="$(git ls-remote --tags origin "refs/tags/$TAG")"; then
    echo "Could not check origin for an existing release tag." >&2
    exit 1
fi
if [[ -n "$REMOTE_TAG" ]]; then
    echo "Remote tag $TAG already exists; refusing to replace it." >&2
    exit 1
fi
if ! CURRENT_BRANCH="$(git symbolic-ref --quiet --short HEAD)"; then
    echo "Check out a branch before running the release helper." >&2
    exit 1
fi

read -r -p "Push branch $CURRENT_BRANCH and release tag $TAG? (y/n): " -n 1 REPLY
echo
if [[ ! "$REPLY" =~ ^[Yy]$ ]]; then
    echo "Release cancelled."
    exit 0
fi

git push origin "$CURRENT_BRANCH"
git tag -a "$TAG" -m "Release $TAG"
git push origin "refs/tags/$TAG"
echo "Tag $TAG pushed. Follow the Release Library workflow in GitHub Actions."
echo "The release assets will be attached after all four native jobs succeed."
