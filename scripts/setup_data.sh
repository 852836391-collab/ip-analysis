#!/usr/bin/env bash
# setup_data.sh — Download ip2region xdb data files from CDN on skill install.
set -euo pipefail

SKILL_DIR="$(cd "$(dirname "$0")/.." && pwd)"
DATA_DIR="${SKILL_DIR}/data"
mkdir -p "${DATA_DIR}"

V4_URL="https://h23.static.yximgs.com/kos/nlav111379/poify/9dd3414dadd14ea6afe671d7a.xdb"
V6_URL="https://h4.static.yximgs.com/kos/nlav111379/poify/9dd3414dadd14ea6afe671d7b.xdb"
V4_FILE="${DATA_DIR}/ip2region_v4.xdb"
V6_FILE="${DATA_DIR}/ip2region_v6.xdb"

download() {
  local name="$1" url="$2" target="$3" size_mb="$4"
  if [ -f "${target}" ] && [ -s "${target}" ]; then
    echo "[setup_data] ${name} already exists, skip download"
    return 0
  fi
  echo "[setup_data] Downloading ${name} (~${size_mb}MB) from CDN..."
  if command -v curl &>/dev/null; then
    curl -fSL --progress-bar -o "${target}" "${url}"
  elif command -v wget &>/dev/null; then
    wget -q --show-progress -O "${target}" "${url}"
  else
    echo "[setup_data] ERROR: curl/wget not found, cannot download ${name}" >&2
    return 1
  fi
  local got_mb
  got_mb="$(du -m "${target}" 2>/dev/null | cut -f1 || echo "?")"
  echo "[setup_data] ${name} downloaded (${got_mb}MB)"
}

download "ip2region_v4.xdb" "${V4_URL}" "${V4_FILE}" "11"
download "ip2region_v6.xdb" "${V6_URL}" "${V6_FILE}" "35"

echo "[setup_data] All data files ready."
