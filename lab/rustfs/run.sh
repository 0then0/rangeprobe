#!/usr/bin/env bash
# Reproduces https://github.com/rustfs/rustfs/issues/2506 against disposable
# RustFS containers and compares RangeProbe with an independent curl/cmp oracle.
#
#   lab/rustfs/run.sh [VERSION...]       default: 1.0.0-alpha.93 1.0.0-alpha.94
#
# Needs: docker, go, curl, cmp. Containers bind 127.0.0.1 only and are removed
# on exit, together with their volumes and the generated file. Results are
# written to lab/rustfs/results/<VERSION>/.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
versions=("$@")
[ ${#versions[@]} -gt 0 ] || versions=(1.0.0-alpha.93 1.0.0-alpha.94)

work=$(mktemp -d "${TMPDIR:-/tmp}/rangeprobe-lab.XXXXXX")
containers=()
cleanup() {
  for c in "${containers[@]:-}"; do
    [ -n "$c" ] || continue
    docker rm -f "$c" >/dev/null 2>&1 || true
    docker volume rm "$c-data" >/dev/null 2>&1 || true
  done
  rm -rf "$work"
}
trap cleanup EXIT

export RUSTFS_ACCESS_KEY=labaccesskey RUSTFS_SECRET_KEY=labsecretkey-0123456789
size=$((24 * 1024 * 1024))

echo "building rangeprobe and the lab adapter"
(cd "$root" && go build -trimpath -o "$work/rangeprobe" ./cmd/rangeprobe)
(cd "$here" && go build -trimpath -o "$work/rustfslab" .)
"$work/rustfslab" gen -out "$work/object.bin" -size "$size" -seed 2506
obj_sha=$(shasum -a 256 "$work/object.bin" | cut -d' ' -f1)
echo "object: $size bytes, sha256 $obj_sha"

for ver in "${versions[@]}"; do
  out="$here/results/$ver"
  mkdir -p "$out"
  name="rp-lab-${ver//[^A-Za-z0-9]/-}-$$"
  image="rustfs/rustfs:$ver"
  docker pull -q "$image" >/dev/null
  digest=$(docker image inspect "$image" --format '{{index .RepoDigests 0}}')
  echo
  echo "=== $image ($digest)"
  containers+=("$name")
  docker run -d --name "$name" -p 127.0.0.1::9000 \
    -e RUSTFS_ACCESS_KEY -e RUSTFS_SECRET_KEY -v "$name-data:/data" "$image" >/dev/null
  port=$(docker port "$name" 9000/tcp | head -n1 | sed 's/.*://')
  endpoint="http://127.0.0.1:$port"
  ready=""
  for _ in $(seq 1 60); do
    code=$(curl -s -o /dev/null -w '%{http_code}' "$endpoint/health" || true)
    if [ "$code" != "000" ] && [ -n "$code" ]; then ready=1; break; fi
    sleep 1
  done
  [ -n "$ready" ] || { echo "RustFS did not start"; docker logs "$name" | tail -20; exit 1; }
  sleep 2

  "$work/rustfslab" put -endpoint "$endpoint" -file "$work/object.bin"
  url=$("$work/rustfslab" presign -endpoint "$endpoint" -expires 1800)

  # Sanity: the full GET must succeed and match, as in the issue.
  curl -s -o "$work/full.bin" "$url"
  if cmp -s "$work/full.bin" "$work/object.bin"; then full=identical; else full=DIFFERENT; fi
  echo "full GET: $full"

  # Independent oracle: ranges from the issue (4 KiB at 0%..100%, 48 KiB tail),
  # compared with slices of the local file using only curl, tail, head and cmp.
  tsv="$out/oracle.tsv"
  printf 'range\thttp_status\tbytes_received\tresult\n' >"$tsv"
  check() { # first last
    local a=$1 b=$2 n=$(($2 - $1 + 1)) st got
    rm -f "$work/part.bin" # curl creates no file for an empty body; never reuse an old one
    st=$(curl -s -o "$work/part.bin" -w '%{http_code}' -H "Range: bytes=$a-$b" "$url" || true)
    got=0; [ ! -f "$work/part.bin" ] || got=$(wc -c <"$work/part.bin" | tr -d ' ')
    { tail -c +$((a + 1)) "$work/object.bin" | head -c "$n" >"$work/exp.bin"; } || true # SIGPIPE from head is expected
    if [ "$got" = "$n" ] && cmp -s "$work/part.bin" "$work/exp.bin"; then r=match; else r=MISMATCH; fi
    printf 'bytes=%s-%s\t%s\t%s\t%s\n' "$a" "$b" "$st" "$got" "$r" >>"$tsv"
  }
  for pct in 0 10 20 30 40 50 60 70 80 90 99; do
    a=$((size * pct / 100)); check "$a" $((a + 4095))
  done
  check $((size - 49152)) $((size - 1))
  cat "$tsv"
  bad=$(grep -c MISMATCH "$tsv" || true)
  echo "oracle: $bad of 12 range reads wrong or empty"

  set +e
  "$work/rangeprobe" reference "$url" "$work/object.bin" --probe-size 48KiB \
    --json "$out/rangeprobe.json" --html "$out/rangeprobe.html" --force >"$out/rangeprobe.txt" 2>&1
  code=$?
  set -e
  echo "rangeprobe exit code: $code"
  grep -E '^(RESULT|  )' "$out/rangeprobe.txt" | head -4 || true

  {
    echo "image: $image"
    echo "digest: $digest"
    echo "platform: $(docker image inspect "$image" --format '{{.Os}}/{{.Architecture}}')"
    echo "docker: $(docker version --format '{{.Server.Version}}' 2>/dev/null || true)"
    echo "object_bytes: $size"
    echo "object_sha256: $obj_sha"
    echo "full_get: $full"
    echo "oracle_bad_ranges: $bad"
    echo "rangeprobe_exit_code: $code"
    echo "rangeprobe_command: rangeprobe reference <presigned-url> object.bin --probe-size 48KiB"
    echo "run_at_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  } >"$out/meta.txt"
done
