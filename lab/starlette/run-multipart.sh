#!/usr/bin/env bash
# Run the pinned multipart cases in a disposable environment.
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
lab="$root/lab/starlette"
work=$(mktemp -d "${TMPDIR:-/tmp}/rangeprobe-starlette-multipart.XXXXXX")
export UV_CACHE_DIR="$work/uv-cache"
export UV_PYTHON_INSTALL_DIR="$work/python"
export UV_PYTHON_BIN_DIR="$work/bin"
export GOCACHE="$work/go-cache"
export PYTHONDONTWRITEBYTECODE=1

echo "Evidence directory: $work"
uv python install 3.13.11
uv venv --python 3.13.11 "$work/venv"
py="$work/venv/bin/python"
uv pip install --python "$py" -r "$lab/requirements.txt"
(cd "$root" && go build -trimpath -o "$work/rangeprobe" ./cmd/rangeprobe)
"$py" "$lab/validate_multipart.py" "$work"
