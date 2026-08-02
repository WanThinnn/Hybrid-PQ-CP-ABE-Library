#!/bin/bash
# =============================================================================
# Hybrid CP-ABE Library Release Script
# Usage: ./scripts/release.sh <version> [--win] [--linux]
# Example: ./scripts/release.sh 3.0.0
#          ./scripts/release.sh 3.0.0 --win
#          ./scripts/release.sh 3.0.0 --linux
#          ./scripts/release.sh 3.0.0 --win --linux
# =============================================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default: build both platforms
BUILD_WIN=false
BUILD_LINUX=false

# Parse arguments
VERSION=""
for arg in "$@"; do
    case $arg in
        --win)
            BUILD_WIN=true
            ;;
        --linux)
            BUILD_LINUX=true
            ;;
        -*)
            echo -e "${RED}Error: Unknown option ${arg}${NC}"
            echo "Usage: ./scripts/release.sh <version> [--win] [--linux]"
            exit 1
            ;;
        *)
            if [ -z "$VERSION" ]; then
                VERSION="$arg"
            fi
            ;;
    esac
done

# If no platform specified, build both
if [ "$BUILD_WIN" = false ] && [ "$BUILD_LINUX" = false ]; then
    BUILD_WIN=true
    BUILD_LINUX=true
fi

# Check if version is provided
if [ -z "$VERSION" ]; then
    echo -e "${RED}Error: Version argument required${NC}"
    echo "Usage: ./scripts/release.sh <version> [--win] [--linux]"
    echo "Examples:"
    echo "  ./scripts/release.sh 3.0.0           # Build both platforms"
    echo "  ./scripts/release.sh 3.0.0 --win     # Build Windows only"
    echo "  ./scripts/release.sh 3.0.0 --linux   # Build Linux only"
    exit 1
fi

TAG="v${VERSION}"

# Normalize version format (remove 'v' prefix if provided)
VERSION="${VERSION#v}"
TAG="v${VERSION}"

echo -e "${BLUE}=== Hybrid CP-ABE Library Release Script ===${NC}"
echo -e "Version: ${GREEN}${VERSION}${NC}"
echo -e "Tag: ${GREEN}${TAG}${NC}"
echo -e "Platforms:"
[ "$BUILD_WIN" = true ] && echo -e "  - ${GREEN}Windows (x86_64)${NC}"
[ "$BUILD_LINUX" = true ] && echo -e "  - ${GREEN}Linux (x86_64)${NC}"
echo ""

# Confirm with user
read -p "Proceed with release ${TAG}? (y/n): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo -e "${YELLOW}Release cancelled${NC}"
    exit 0
fi

# Step 1: Check if tag exists locally
if git tag -l | grep -q "^${TAG}$"; then
    echo -e "${YELLOW}[1/6] Deleting existing local tag ${TAG}...${NC}"
    git tag -d "${TAG}"
else
    echo -e "${GREEN}[1/6] No existing local tag to delete${NC}"
fi

# Step 2: Check if tag exists on remote
if git ls-remote --tags origin | grep -q "refs/tags/${TAG}"; then
    echo -e "${YELLOW}[2/6] Deleting existing remote tag ${TAG}...${NC}"
    git push origin ":refs/tags/${TAG}"
else
    echo -e "${GREEN}[2/6] No existing remote tag to delete${NC}"
fi

# Step 3: Update VERSION file
echo -e "${BLUE}[3/6] Updating VERSION file...${NC}"
echo "${VERSION}" > VERSION

# Step 4: Update README badge (optional - only if badge exists)
if grep -q "version-.*-blue" README.md; then
    echo -e "${BLUE}[4/6] Updating README badge...${NC}"
    # Update version badge: version-X.X.X-blue or version-X.X.X--RC-blue
    sed -i "s/version-[0-9.]*\(-\{0,2\}[A-Za-z0-9]*\)\{0,1\}-blue/version-${VERSION//-/--}-blue/g" README.md
else
    echo -e "${GREEN}[4/6] No README badge to update${NC}"
fi

# Step 5: Commit and push changes
echo -e "${BLUE}[5/6] Committing and pushing changes...${NC}"
git add VERSION README.md 2>/dev/null || true
if git diff --cached --quiet; then
    echo -e "${GREEN}No changes to commit${NC}"
else
    git commit -m "chore: bump version to ${VERSION}"
    CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD)
    git push origin "$CURRENT_BRANCH"
fi

# Step 6: Create and push new tag
echo -e "${BLUE}[6/6] Creating and pushing tag ${TAG}...${NC}"
git tag "${TAG}"
git push origin "${TAG}"

# Export build flags for GitHub Actions workflow
echo "BUILD_WIN=${BUILD_WIN}" >> "$GITHUB_ENV" 2>/dev/null || true
echo "BUILD_LINUX=${BUILD_LINUX}" >> "$GITHUB_ENV" 2>/dev/null || true

echo ""
echo -e "${GREEN}=== Release ${TAG} completed! ===${NC}"
echo -e "GitHub Actions will now:"
echo -e "  - Build library packages for:"
[ "$BUILD_WIN" = true ] && echo -e "    ${GREEN}✓ Windows (x86_64)${NC}"
[ "$BUILD_LINUX" = true ] && echo -e "    ${GREEN}✓ Linux (x86_64)${NC}"
echo ""
echo -e "Package contents:"
echo -e "  ${YELLOW}lib/${NC}"
[ "$BUILD_WIN" = true ] && echo -e "    - libhybrid-pq-cp-abe.dll  (dynamic library)"
[ "$BUILD_WIN" = true ] && echo -e "    - libhybrid-pq-cp-abe.lib  (static library)"
[ "$BUILD_LINUX" = true ] && echo -e "    - libhybrid-pq-cp-abe.so   (shared library)"
[ "$BUILD_LINUX" = true ] && echo -e "    - libhybrid-pq-cp-abe.a    (static library)"
echo -e "  ${YELLOW}include/${NC}"
echo -e "    - hybrid-pq-cp-abe.h"
echo -e "    - rabe/"
echo -e "      - rabe.h"
echo ""
echo -e "Release artifacts:"
[ "$BUILD_WIN" = true ] && echo -e "  - libhybrid-pq-cp-abe_win_x86_64_v${VERSION}.zip"
[ "$BUILD_LINUX" = true ] && echo -e "  - libhybrid-pq-cp-abe_linux_x86_64_v${VERSION}.zip"
echo ""
echo -e "Check progress at: ${BLUE}https://github.com/WanThinnn/Hybrid-PQ-CP-ABE-Library/actions${NC}"
