#!/bin/bash
# Smart Sync built C++ libraries to Go plugin directory

TARGET_DIR="vault-plugin-abe/lib"
mkdir -p "$TARGET_DIR"

echo "Checking for library updates..."

# Use cp -u to only copy when the source is newer than the destination
# -u, --update: copy only when the SOURCE file is newer than the destination file or when the destination file is missing

if [ -d "../../lib" ]; then
    find ../../lib -maxdepth 1 -type f \( -name "*.a" -o -name "*.so" -o -name "*.dylib" -o -name "*.lib" -o -name "*.dll" \) \
        -exec cp -uv {} "$TARGET_DIR"/ \; 2>/dev/null || true
fi

echo "Libraries synced to $TARGET_DIR successfully!"
