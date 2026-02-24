#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if ! command -v doxygen >/dev/null 2>&1; then
  echo "doxygen not found. Install it first (e.g. on Arch: sudo pacman -S doxygen graphviz)" >&2
  exit 1
fi

echo "Generating Doxygen docs..."
doxygen Doxyfile

echo "Done. Open: docs/build/html/index.html"
