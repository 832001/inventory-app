#!/usr/bin/env bash
# Build inventory_app_v3.zip from the current directory.
# Run from the app_v3/ root:
#   chmod +x build_zip.sh && ./build_zip.sh

set -euo pipefail

ROOT_NAME="inventory_app_v3"
OUT="${ROOT_NAME}.zip"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "▶ Copying files to staging area…"
mkdir -p "$TMP/$ROOT_NAME"
cp -r app.py config.py lifecycle.py export_utils.py requirements.txt .env.example README.md "$TMP/$ROOT_NAME/" 2>/dev/null || true
cp -r adapters collectors "$TMP/$ROOT_NAME/"
[ -d templates ] && cp -r templates "$TMP/$ROOT_NAME/"
[ -d static ]    && cp -r static    "$TMP/$ROOT_NAME/"
cp build_zip.sh "$TMP/$ROOT_NAME/" || true

echo "▶ Cleaning Python caches…"
find "$TMP/$ROOT_NAME" -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
find "$TMP/$ROOT_NAME" -name '*.pyc' -delete 2>/dev/null || true

echo "▶ Smoke-testing Python syntax…"
python3 -m compileall -q "$TMP/$ROOT_NAME" || {
    echo "⚠ compileall reported errors — fix them before deploying."
    exit 1
}

echo "▶ Writing zip…"
( cd "$TMP" && zip -qr "$OLDPWD/$OUT" "$ROOT_NAME" )
echo
echo "✅ Created $OUT ($(du -h "$OUT" | cut -f1))"
echo "   Contents:"
unzip -l "$OUT" | sed 's/^/   /'
