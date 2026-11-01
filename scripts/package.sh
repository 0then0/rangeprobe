#!/usr/bin/env bash
# Builds release archives for all supported platforms into dist/ and writes
# dist/SHA256SUMS. Needs: go, tar, gzip, zip, and sha256sum or shasum.
#   scripts/package.sh
# The version comes from internal/version/version.go. Binaries are built with
# CGO_ENABLED=0 and -trimpath. The script verifies the archives it produced and
# runs the binary built for the host.
set -euo pipefail
cd "$(dirname "$0")/.."

version=$(sed -n 's/^const Version = "\(.*\)"$/\1/p' internal/version/version.go)
targets="linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64"
rm -rf dist
mkdir -p dist
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT

sha256() { if command -v sha256sum >/dev/null; then sha256sum "$@"; else shasum -a 256 "$@"; fi; }
host_os=$(go env GOHOSTOS) host_arch=$(go env GOHOSTARCH)

for t in $targets; do
  os=${t%/*} arch=${t#*/}
  name="rangeprobe_${version}_${os}_${arch}"
  bin=rangeprobe; [ "$os" = windows ] && bin=rangeprobe.exe
  mkdir -p "$stage/$name"
  CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build -trimpath -ldflags "-s -w" -o "$stage/$name/$bin" ./cmd/rangeprobe
  cp LICENSE README.md CHANGELOG.md "$stage/$name/"
  if [ "$os" = windows ]; then
    (cd "$stage" && zip -q -X -r "$OLDPWD/dist/$name.zip" "$name")
  else
    (cd "$stage" && tar -cf - "$name" | gzip -n -9 >"$OLDPWD/dist/$name.tar.gz")
  fi
  if [ "$os" = "$host_os" ] && [ "$arch" = "$host_arch" ]; then
    out=$("$stage/$name/$bin" version | head -n1)
    case $out in "rangeprobe $version "*) ;; *) echo "built binary reports '$out', expected version $version" >&2; exit 1 ;; esac
  fi
done

(cd dist && sha256 *.tar.gz *.zip >SHA256SUMS && sha256 -c SHA256SUMS >/dev/null)
# Every platform archive must contain the binary and the license. The listing
# is captured first: grep -q closing the pipe early would trip pipefail.
for f in dist/*.tar.gz; do
  list=$(tar -tzf "$f")
  grep -q '/rangeprobe$' <<<"$list" && grep -q '/LICENSE$' <<<"$list" || { echo "bad archive $f" >&2; exit 1; }
done
for f in dist/*.zip; do
  list=$(unzip -Z1 "$f")
  grep -q '/rangeprobe.exe$' <<<"$list" && grep -q '/LICENSE$' <<<"$list" || { echo "bad archive $f" >&2; exit 1; }
done
ls -l dist
