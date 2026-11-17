#!/usr/bin/env bash
# build.sh – konfiguruje i buduje projekt do katalogu ./build
#
# Użycie: bash scripts/build.sh [TYP]
#   TYP: RelWithDebInfo (domyślnie, -O2 -g) | Debug (-O0 -g, bez _FORTIFY_SOURCE) | Release

set -euo pipefail

# Przechodzimy do katalogu głównego repo niezależnie od tego, skąd uruchomiono skrypt.
cd "$(dirname "$0")/.."

BUILD_TYPE="${1:-RelWithDebInfo}"

cmake -S . -B build -DCMAKE_BUILD_TYPE="$BUILD_TYPE"
cmake --build build -j"$(nproc)"

echo
echo "Gotowe ($BUILD_TYPE). Binarki w katalogu: $(pwd)/build"
