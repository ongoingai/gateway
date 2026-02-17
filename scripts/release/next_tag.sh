#!/usr/bin/env sh
set -eu

CONFIG_FILE="${1:-release/version.conf}"

if [ ! -f "$CONFIG_FILE" ]; then
	echo "error: version config not found: $CONFIG_FILE" >&2
	exit 1
fi

base_version="$(
	sed -nE \
		's/^[[:space:]]*base_version[[:space:]]*=[[:space:]]*"?([0-9]+\.[0-9]+)"?[[:space:]]*$/\1/p' \
		"$CONFIG_FILE" | tail -n1
)"

if [ -z "$base_version" ]; then
	echo "error: base_version is missing or invalid in $CONFIG_FILE" >&2
	exit 1
fi

latest_tag="$(
	git tag --list "v${base_version}.*" \
		| grep -E "^v${base_version}\.[0-9]+$" \
		| sort -V \
		| tail -n1 || true
)"

if [ -z "$latest_tag" ]; then
	printf 'v%s.0\n' "$base_version"
	exit 0
fi

latest_patch="${latest_tag##*.}"
next_patch=$((latest_patch + 1))
printf 'v%s.%s\n' "$base_version" "$next_patch"
