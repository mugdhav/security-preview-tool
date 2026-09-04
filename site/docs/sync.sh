#!/bin/sh
# Local preview helper. Mirrors the "Stage documentation sources" step in
# .github/workflows/pages.yml so the docs pages render when served locally.
#
#   sh site/docs/sync.sh
#   (cd site && python -m http.server) && open http://localhost:8000/docs/
set -e
cd "$(dirname "$0")"

mkdir -p content/images
cp ../../docs/DESKTOP.md content/desktop.md
cp ../../docs/USAGE.md   content/cli.md
cp ../../docs/CURSOR.md  content/skill.md
cp ../../docs/images/*.png content/images/ 2>/dev/null || true
cp ../../docs/images/*.svg content/images/ 2>/dev/null || true

echo "Staged docs/ -> site/docs/content/. Serve site/ over HTTP to preview."
