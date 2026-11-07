#!/usr/bin/env bash
# Verifies that the release version is consistent.
#   scripts/check-release.sh            version is semver and CHANGELOG has an entry
#   scripts/check-release.sh --tag vX.Y.Z   additionally: the tag equals the version
#                                       and the CHANGELOG entry carries a date
set -euo pipefail
cd "$(dirname "$0")/.."

version=$(sed -n 's/^const Version = "\(.*\)"$/\1/p' internal/version/version.go)
[ -n "$version" ] || { echo "cannot read Version from internal/version/version.go" >&2; exit 1; }
if ! [[ $version =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]; then
  echo "version $version is not semantic (MAJOR.MINOR.PATCH[-prerelease])" >&2; exit 1
fi
heading=$(grep -m1 -F "## [$version]" CHANGELOG.md || true)
[ -n "$heading" ] || { echo "CHANGELOG.md has no '## [$version]' section" >&2; exit 1; }

web_version=$(sed -n 's/^export const VERSION = "\(.*\)";$/\1/p' web/js/config.js)
[ "$web_version" = "$version" ] || { echo "web/js/config.js VERSION '$web_version' does not match $version in internal/version/version.go" >&2; exit 1; }

if [ "${1:-}" = "--tag" ]; then
  tag=${2:?usage: check-release.sh --tag vX.Y.Z}
  [ "$tag" = "v$version" ] || { echo "tag $tag does not match version v$version in internal/version/version.go" >&2; exit 1; }
  if ! [[ $heading =~ ^##\ \[$version\]\ -\ [0-9]{4}-[0-9]{2}-[0-9]{2}$ ]]; then
    echo "CHANGELOG heading must be '## [$version] - YYYY-MM-DD' before tagging, found: $heading" >&2; exit 1
  fi
fi
echo "release metadata ok: version $version"
