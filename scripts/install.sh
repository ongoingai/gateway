#!/usr/bin/env sh
set -eu

APP_NAME="ongoingai"
BASE_URL="${ONGOINGAI_INSTALL_BASE_URL:-https://ongoingai.dev}"
VERSION="${ONGOINGAI_VERSION:-latest}"
INSTALL_DIR="${ONGOINGAI_INSTALL_DIR:-/usr/local/bin}"

require_command() {
	if ! command -v "$1" >/dev/null 2>&1; then
		echo "error: required command not found: $1" >&2
		exit 1
	fi
}

sha256_file() {
	file="$1"

	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$file" | awk '{print $1}'
		return 0
	fi

	if command -v shasum >/dev/null 2>&1; then
		shasum -a 256 "$file" | awk '{print $1}'
		return 0
	fi

	if command -v openssl >/dev/null 2>&1; then
		openssl dgst -sha256 "$file" | awk '{print $NF}'
		return 0
	fi

	echo "error: no SHA-256 tool found (sha256sum, shasum, or openssl)" >&2
	exit 1
}

detect_os() {
	case "$(uname -s)" in
		Linux) echo "linux" ;;
		Darwin) echo "darwin" ;;
		MINGW*|MSYS*|CYGWIN*) echo "windows" ;;
		*)
			echo "error: unsupported operating system: $(uname -s)" >&2
			exit 1
			;;
	esac
}

detect_arch() {
	case "$(uname -m)" in
		x86_64|amd64) echo "amd64" ;;
		arm64|aarch64) echo "arm64" ;;
		*)
			echo "error: unsupported architecture: $(uname -m)" >&2
			exit 1
			;;
	esac
}

download_binary() {
	tmpfile="$1"
	asset="$2"
	version="$3"
	base_url="$4"

	tag="$version"
	tag_without_v="$version"
	case "$version" in
		v*) tag_without_v="${version#v}" ;;
	esac

	set -- \
		"$base_url/releases/$version/$asset" \
		"https://github.com/ongoingai/gateway/releases/download/$tag/$asset" \
		"https://github.com/ongoingai/gateway/releases/download/v$tag_without_v/$asset"

	if [ "$version" = "latest" ]; then
		set -- \
			"$base_url/releases/latest/$asset" \
			"https://github.com/ongoingai/gateway/releases/latest/download/$asset"
	fi

	for url in "$@"; do
		echo "trying $url"
		if curl -fsSL "$url" -o "$tmpfile"; then
			echo "downloaded from $url"
			return 0
		fi
	done

	return 1
}

verify_binary_checksum() {
	binary_path="$1"
	asset="$2"
	version="$3"
	base_url="$4"
	checksum_tmp="$5"

	actual_hash="$(sha256_file "$binary_path")"

	tag="$version"
	tag_without_v="$version"
	case "$version" in
		v*) tag_without_v="${version#v}" ;;
	esac

	set -- \
		"$base_url/releases/$version/checksums.txt" \
		"https://github.com/ongoingai/gateway/releases/download/$tag/checksums.txt" \
		"https://github.com/ongoingai/gateway/releases/download/v$tag_without_v/checksums.txt"

	if [ "$version" = "latest" ]; then
		set -- \
			"$base_url/releases/latest/checksums.txt" \
			"https://github.com/ongoingai/gateway/releases/latest/download/checksums.txt"
	fi

	for url in "$@"; do
		echo "trying checksum $url"
		if ! curl -fsSL "$url" -o "$checksum_tmp"; then
			continue
		fi

		expected_hash="$(awk -v asset="$asset" '{name=$2; gsub(/^\*/, "", name); if (name == asset) {print $1; exit}}' "$checksum_tmp")"
		if [ -z "$expected_hash" ]; then
			continue
		fi

		if [ "$expected_hash" = "$actual_hash" ]; then
			echo "checksum verified via $url"
			return 0
		fi

		echo "error: checksum mismatch for $asset" >&2
		echo "expected: $expected_hash" >&2
		echo "actual:   $actual_hash" >&2
		exit 1
	done

	return 1
}

install_binary() {
	src="$1"
	install_dir="$2"
	target="$install_dir/$APP_NAME"

	if [ -d "$install_dir" ] && [ -w "$install_dir" ]; then
		install -m 0755 "$src" "$target"
		return
	fi

	if command -v sudo >/dev/null 2>&1; then
		sudo mkdir -p "$install_dir"
		sudo install -m 0755 "$src" "$target"
		return
	fi

	echo "error: cannot write to $install_dir and sudo is not available" >&2
	exit 1
}

require_command curl
require_command uname
require_command install
require_command awk
require_command mktemp

os="$(detect_os)"
arch="$(detect_arch)"
ext=""
if [ "$os" = "windows" ]; then
	ext=".exe"
fi
asset="${APP_NAME}_${os}_${arch}${ext}"

tmpfile="$(mktemp)"
checksum_tmp="$(mktemp)"
cleanup() {
	rm -f "$tmpfile" "$checksum_tmp"
}
trap cleanup EXIT INT TERM

if ! download_binary "$tmpfile" "$asset" "$VERSION" "$BASE_URL"; then
	echo "error: failed to download $asset for version $VERSION" >&2
	echo "hint: set ONGOINGAI_INSTALL_BASE_URL or ONGOINGAI_VERSION if needed" >&2
	exit 1
fi

if ! verify_binary_checksum "$tmpfile" "$asset" "$VERSION" "$BASE_URL" "$checksum_tmp"; then
	echo "error: failed to verify checksum for $asset ($VERSION)" >&2
	echo "hint: ensure release checksums.txt is available from your install source" >&2
	exit 1
fi

install_binary "$tmpfile" "$INSTALL_DIR"

echo "installed $APP_NAME to $INSTALL_DIR/$APP_NAME"
echo "run: $APP_NAME version"
