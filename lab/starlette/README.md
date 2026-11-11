# Starlette #3567: historical If-Range regression

This validates an **already fixed historical case**, not a new upstream defect.
[PR #3567](https://github.com/Kludex/starlette/pull/3567) was merged on 2026-09-27.
GitHub's pull/commit APIs were checked on 2026-11-11:

- Merge/squash commit: `85c3b7434fd6b58596486dbe93cfe605ee358881`.
- Its sole parent: `56d8858633c8e04113a231ddaf3e47acf1e3516d`.
- The patch rejects `http_if_range.startswith("W/")` before the equality check.

The fixture is exactly `file content` (12 bytes). `/strong` uses custom ETag
`"strong-control"`; `/weak` uses `W/"a_weak_etag"`, matching upstream's regression
setup. `FileResponse` generates `Last-Modified` from the fixture's stat information.
Both revisions serve the same file. Nothing controls or switches a remote resource.

[RFC 9110 section 13.1.5](https://www.rfc-editor.org/rfc/rfc9110.html#section-13.1.5)
requires strong entity-tag comparison. A weak request tag cannot satisfy it, even
when the response has the same raw weak ETag. Range must be ignored. Clients MUST
NOT generate weak If-Range; this deliberately invalid input is an opt-in server
conformance test. [Section 14.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-14.2)
permits ignoring Range even when the validator matches.

## Reproduce

Requires `uv`, Go from the root `go.mod`, internet access and free loopback ports
18761/18762. From the repository root:

```sh
bash lab/starlette/run.sh
```

The script creates a new temporary directory, downloads exact source archives and
CPython 3.13.11, installs only the pinned validation dependencies in a disposable
venv, starts two Uvicorn servers and builds the public Go CLI. It does not change
an existing Python environment. Servers are stopped on exit; the directory remains
for inspection and can be deleted afterwards. Source archive SHA-256 values and
installed dependency pins are saved beside the generated reports.

Commands executed for each server (parent on 18761, fixed on 18762):

```sh
rangeprobe if-range http://127.0.0.1:18761/strong --probe-size 5 --json parent-strong.json --html parent-strong.html
rangeprobe if-range http://127.0.0.1:18761/weak --probe-size 5 --weak-if-range --json parent-weak.json --html parent-weak.html
rangeprobe if-range http://127.0.0.1:18762/strong --probe-size 5 --json fixed-strong.json --html fixed-strong.html
rangeprobe if-range http://127.0.0.1:18762/weak --probe-size 5 --weak-if-range --json fixed-weak.json --html fixed-weak.html
```

`validate.py` independently repeats every executed probe using Python's standard
library `http.client`, replaying the exact sent validator from its base64 evidence.
It asserts status, ETag, Content-Range, Content-Length, Last-Modified presence and
actual body bytes (`file ` for 206, `file content` for 200), then saves `oracle.json`.
No HTTP client library or Starlette TestClient is involved in this oracle.

## Observed on 2026-11-11

Compact results are preserved in [results/representative.txt](results/representative.txt),
exact revisions/archive digests in [results/pins.json](results/pins.json), and independent
status/header/byte evidence in [results/oracle.json](results/oracle.json).

```text
parent /strong: baseline 206 (5 B), matching 206 (5 B), mismatching 200 (12 B), exit 0
fixed  /strong: baseline 206 (5 B), matching 206 (5 B), mismatching 200 (12 B), exit 0
parent /weak:   baseline 206 (5 B), same raw weak If-Range 206 (5 B), violation, exit 1
fixed  /weak:   baseline 206 (5 B), same raw weak If-Range 200 (12 B), fallback, exit 3
```

The fixed weak run exits 3 because its baseline has no usable **strong** ETag:
main matching/mismatching strong checks are explicitly skipped. The weak probe's
fallback succeeded, but the run cannot claim conditional resume support. The parent
exits 1 because the false weak condition demonstrably produced 206. This agrees
with upstream's regression. No new upstream issue is required.
