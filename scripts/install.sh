#!/usr/bin/env sh
set -eu

REPO="ongoingai/gateway"
BIN_NAME="ongoingai"
INSTALL_DIR_DEFAULT="/usr/local/bin"
INSTALL_DIR_USER="$HOME/.local/bin"

log() { printf "%s\n" "$*" >&2; }
die() { log "Error: $*"; exit 1; }

download() {
  url="$1"
  out="$2"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$url" -o "$out"
  elif command -v wget >/dev/null 2>&1; then
    wget -qO "$out" "$url"
  else
    die "Need curl or wget to download files"
  fi
}

json_get_tag() {
  sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1
}

detect_os() {
  os="$(uname -s | tr '[:upper:]' '[:lower:]')"
  case "$os" in
    darwin) echo "darwin" ;;
    linux)  echo "linux" ;;
    *) die "Unsupported OS: $os (supported: macOS, Linux)" ;;
  esac
}

detect_arch() {
  arch="$(uname -m)"
  case "$arch" in
    x86_64|amd64) echo "amd64" ;;
    arm64|aarch64) echo "arm64" ;;
    *) die "Unsupported architecture: $arch (supported: amd64, arm64)" ;;
  esac
}

pick_install_dir() {
  if [ -d "$INSTALL_DIR_DEFAULT" ] && [ -w "$INSTALL_DIR_DEFAULT" ]; then
    echo "$INSTALL_DIR_DEFAULT"
    return
  fi
  mkdir -p "$INSTALL_DIR_USER"
  echo "$INSTALL_DIR_USER"
}

ensure_path_hint() {
  dir="$1"
  case ":$PATH:" in
    *":$dir:"*) return ;;
    *)
      log ""
      log "Note: $dir is not in your PATH."
      log "Add this to your shell profile (~/.zshrc, ~/.bashrc):"
      log "  export PATH=\"$dir:\$PATH\""
      ;;
  esac
}

sha256_file() {
  file="$1"
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$file" | awk '{print $1}'
  elif command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$file" | awk '{print $1}'
  else
    die "No sha256 tool found (shasum or sha256sum)."
  fi
}

# ---- main ----
OS="$(detect_os)"
ARCH="$(detect_arch)"

log "OngoingAI installer"
log "Detected: $OS/$ARCH"
log "Repo: $REPO"
log ""

TAG="${ONGOINGAI_VERSION:-}"
if [ -z "${TAG}" ]; then
  log "Resolving latest release..."
  tmpjson="$(mktemp)"
  download "https://api.github.com/repos/$REPO/releases/latest" "$tmpjson"
  TAG="$(cat "$tmpjson" | json_get_tag)"
  rm -f "$tmpjson"
  [ -n "$TAG" ] || die "Could not resolve latest release tag. Set ONGOINGAI_VERSION=vX.Y.Z and retry."
fi

ASSET="${BIN_NAME}_${OS}_${ARCH}"
URL="https://github.com/$REPO/releases/download/$TAG/$ASSET"

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

bin_tmp="$tmpdir/$BIN_NAME"
log "Installing $BIN_NAME $TAG"
log "Downloading: $URL"
download "$URL" "$bin_tmp"

# Verify checksum (your workflow always uploads checksums.txt)
if [ "${ONGOINGAI_VERIFY:-1}" = "1" ]; then
  checksum_url="https://github.com/$REPO/releases/download/$TAG/checksums.txt"
  checksum_file="$tmpdir/checksums.txt"
  log "Downloading checksums: $checksum_url"
  download "$checksum_url" "$checksum_file"

  expected="$(awk -v asset="$ASSET" '
    {name=$2; gsub(/^\*/, "", name); if (name == asset) {print $1; exit}}
  ' "$checksum_file")"
  [ -n "$expected" ] || die "checksums.txt found but no entry for $ASSET"

  actual="$(sha256_file "$bin_tmp")"
  [ "$expected" = "$actual" ] || die "Checksum mismatch for $ASSET"

  log "Checksum verified (sha256)."
fi

install_dir="$(pick_install_dir)"
dest="$install_dir/$BIN_NAME"

log "Installing to: $dest"
mv "$bin_tmp" "$dest"
chmod +x "$dest"

log ""
log "✅ Installed: $dest"
ensure_path_hint "$install_dir"

log ""
log "Next:"
log "  $BIN_NAME version"
log "  $BIN_NAME install gateway"
log "  $BIN_NAME serve"
