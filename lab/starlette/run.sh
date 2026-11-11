#!/usr/bin/env bash
# Disposable historical conformance validation; never touches an existing venv.
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/rangeprobe-starlette.XXXXXX")
export UV_CACHE_DIR="$work/uv-cache"
export UV_PYTHON_INSTALL_DIR="$work/python"
export UV_PYTHON_BIN_DIR="$work/bin"
export GOCACHE="$work/go-cache"
export PYTHONDONTWRITEBYTECODE=1
parent=56d8858633c8e04113a231ddaf3e47acf1e3516d
fixed=85c3b7434fd6b58596486dbe93cfe605ee358881
pids=()
cleanup() {
  for pid in "${pids[@]}"; do kill "$pid" 2>/dev/null || true; done
  for pid in "${pids[@]}"; do wait "$pid" 2>/dev/null || true; done
}
trap cleanup EXIT
uv python install 3.13.11
uv venv --python 3.13.11 "$work/venv"
py="$work/venv/bin/python"
uv pip install --python "$py" -r "$root/lab/starlette/requirements.txt"
"$py" - "$work" "$parent" "$fixed" <<'PY'
import hashlib, io, json, pathlib, sys, tarfile, urllib.request
work = pathlib.Path(sys.argv[1])
pins = {"python": sys.version, "revisions": {}}
for name, sha in zip(["parent", "fixed"], sys.argv[2:]):
    data = urllib.request.urlopen(f"https://codeload.github.com/Kludex/starlette/tar.gz/{sha}").read()
    target = work / name
    target.mkdir()
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        archive.extractall(target, filter="data")
    pins["revisions"][name] = {"commit": sha, "archive_sha256": hashlib.sha256(data).hexdigest()}
(work / "pins.json").write_text(json.dumps(pins, indent=2) + "\n")
PY
mkdir "$work/results"
cp "$work/pins.json" "$work/results/pins.json"
uv pip freeze --python "$py" > "$work/results/dependencies.txt"
for name in parent fixed; do
  sha=$parent
  port=18761
  if [ "$name" = fixed ]; then sha=$fixed; port=18762; fi
  PYTHONPATH="$work/$name/starlette-$sha:$root/lab/starlette" \
    "$py" -m uvicorn app:app --host 127.0.0.1 --port "$port" --lifespan off \
    --http h11 --loop asyncio --no-access-log > "$work/$name.log" 2>&1 &
  pids+=("$!")
done
"$py" - <<'PY'
import http.client, time
for port in [18761, 18762]:
    for attempt in range(100):
        try:
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=1)
            c.request("GET", "/strong", headers={"Range": "bytes=0-4"})
            r = c.getresponse()
            assert r.status == 206 and r.read(1024) == b"file "
            c.close()
            break
        except (OSError, AssertionError):
            if attempt == 99:
                raise
            time.sleep(.05)
PY
(cd "$root" && go build -trimpath -o "$work/rangeprobe" ./cmd/rangeprobe)
"$py" "$root/lab/starlette/validate.py" "$work/rangeprobe" "$work/results" | tee "$work/results/representative.txt"
echo "Evidence: $work/results"
