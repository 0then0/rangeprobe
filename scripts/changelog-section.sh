#!/usr/bin/env bash
# Prints the CHANGELOG.md section of one version (without its heading).
set -euo pipefail
cd "$(dirname "$0")/.."
version=${1:?usage: changelog-section.sh X.Y.Z}
awk -v v="$version" '
  index($0, "## [" v "]") == 1 { on = 1; next }
  on && /^## \[/ { exit }
  on { print }
' CHANGELOG.md
