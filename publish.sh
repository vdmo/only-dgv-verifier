#!/usr/bin/env bash
# Builds a binary-first DGV release package for the new verifier repository.
# Run from the dgv/ directory: bash publish.sh
set -euo pipefail

REMOTE="${REMOTE:-git@github.com:vdmo/only-dgv-verifier.git}"
SRC_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SRC_DIR/.." && pwd)"
OUT_DIR="${OUT_DIR:-$SRC_DIR/release}"
VERSION="${VERSION:-0.7.0}"
PKG_NAME="only-dgv-verifier-${VERSION}"
PKG_ROOT="$OUT_DIR/$PKG_NAME"
SKIP_BUILD=0
PUSH=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --skip-build)
      SKIP_BUILD=1
      ;;
    --push)
      PUSH=1
      ;;
    --out)
      OUT_DIR="$2"
      shift
      ;;
    --remote)
      REMOTE="$2"
      shift
      ;;
    --version)
      VERSION="$2"
      shift
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 2
      ;;
  esac
  shift
done

mkdir -p "$OUT_DIR"

if [[ "$SKIP_BUILD" -eq 0 ]]; then
  echo "==> Building release binaries"
  cargo build --release --manifest-path "$REPO_ROOT/dgv-verifier/Cargo.toml"
  cargo build --release --manifest-path "$REPO_ROOT/only-gate/Cargo.toml"
fi

pick_binary() {
  local name="$1"
  local dirs=(
    "$REPO_ROOT/target/release"
    "$REPO_ROOT/dgv-verifier/target/release"
    "$REPO_ROOT/only-gate/target/release"
  )

  for dir in "${dirs[@]}"; do
    if [[ -f "$dir/$name.exe" ]]; then
      echo "$dir/$name.exe"
      return 0
    elif [[ -f "$dir/$name" ]]; then
      echo "$dir/$name"
      return 0
    fi
  done

  echo "Binary not found for $name in ${dirs[*]}" >&2
  exit 1
}

DGV_BIN="$(pick_binary "dgv-verifier")"
GATE_BIN="$(pick_binary "only-gate")"

rm -rf "$PKG_ROOT"
mkdir -p "$PKG_ROOT"

if command -v rsync >/dev/null 2>&1; then
  rsync -a --delete \
    --exclude='node_modules/' \
    --exclude='dist/' \
    --exclude='dist-ssr/' \
    --exclude='.vscode/' \
    --exclude='dgv-desktop/' \
    --exclude='dgv-tui/' \
    --exclude='release/' \
    --exclude='publish.sh' \
    --exclude='__pycache__/' \
    --exclude='*.py[cod]' \
    "$SRC_DIR/" "$PKG_ROOT/"
else
  cp -a "$SRC_DIR/." "$PKG_ROOT/"
  rm -rf "$PKG_ROOT/dgv-desktop" "$PKG_ROOT/dgv-tui" "$PKG_ROOT/release"
  find "$PKG_ROOT" -type d -name '__pycache__' -prune -exec rm -rf {} +
  find "$PKG_ROOT" -type f -name '*.py[cod]' -delete
fi

mkdir -p "$PKG_ROOT/binaries"
cp "$DGV_BIN" "$PKG_ROOT/binaries/dgv-verifier"
cp "$GATE_BIN" "$PKG_ROOT/binaries/only-gate"
chmod +x "$PKG_ROOT/binaries/dgv-verifier" "$PKG_ROOT/binaries/only-gate"

python3 - "$PKG_ROOT/README.md" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
path.write_text("""# ONLY DGV verifier bundle

This package contains the DGV test-card suite for the v0.7.0 / 55-card standard together with the native release binaries for the verifier and cryptographic gate.

## Contents
- test_cards/: 55 JSON test cards for the current standard
- evidence/: generated evidence bundles and receipts
- versions/: historical registry snapshots
- binaries/dgv-verifier: native Rust verifier binary
- binaries/only-gate: native cryptographic validation binary

## Quick start
```bash
./binaries/dgv-verifier --help
./binaries/only-gate --check=signature --message=hello
```

## Notes
- The desktop and TUI assets were intentionally excluded from this bundle.
- The Python harness remains available in the package root for local inspection and replay.
""")
PY

python3 - "$PKG_ROOT/.gitignore" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
path.write_text("""__pycache__/
*.py[cod]
*.log
""")
PY

if command -v zip >/dev/null 2>&1; then
  (cd "$OUT_DIR" && zip -r "${PKG_NAME}.zip" "$PKG_NAME" >/dev/null)
  ARCHIVE="$OUT_DIR/${PKG_NAME}.zip"
else
  tar -czf "$OUT_DIR/${PKG_NAME}.tar.gz" -C "$OUT_DIR" "$PKG_NAME"
  ARCHIVE="$OUT_DIR/${PKG_NAME}.tar.gz"
fi

echo "==> Package ready at $ARCHIVE"

if [[ "$PUSH" -eq 1 ]]; then
  echo "==> Initialising temporary git repo for $REMOTE"
  tmp_dir="$(mktemp -d)"
  cp -a "$PKG_ROOT/." "$tmp_dir/"
  cd "$tmp_dir"
  git init -b main >/dev/null
  git config user.name "vdmo"
  git config user.email "vdmo@users.noreply.github.com"
  git add .
  git commit -m "Publish ONLY DGV verifier bundle ${VERSION}" >/dev/null
  git remote add origin "$REMOTE"
  git push --force -u origin main
  echo "Published to $REMOTE"
fi

