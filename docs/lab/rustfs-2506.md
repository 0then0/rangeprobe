# Lab: RustFS range reads (rustfs/rustfs#2506)

An external acceptance case for RangeProbe. It is not required for any normal test and nothing in
`go test` touches Docker or the network.

## The reported defect

[rustfs/rustfs#2506](https://github.com/rustfs/rustfs/issues/2506), opened 2026-04-12 against
`1.0.0-alpha.93`, closed as completed on 2026-04-25. The reporter saw `206 Partial Content`
responses with a `Content-Length` matching the requested range and an empty body, for ranges beyond
a file-size dependent offset (around 40 to 60 percent of the file), while a full `GET` worked. Trino
failed to read Parquet footers and boto3 raised `IncompleteRead`.

The issue links the fix [rustfs/rustfs#2493](https://github.com/rustfs/rustfs/pull/2493)
("fix(storage): fix critical bug in range calculation"), merged as commit
`c8c71e34b6bb4f757f2a47b49f1bc2a807ce846c` on 2026-04-11. The issue being closed is not evidence
about any current version; the lab tests only the two pinned versions below.

## Pinned versions

The GitHub compare API reports that `1.0.0-alpha.93` is behind that commit and `1.0.0-alpha.94`
contains it, so they are the last version without and the first version with the fix.

| Role | Image | Digest | Platform |
| --- | --- | --- | --- |
| buggy | `rustfs/rustfs:1.0.0-alpha.93` | `sha256:f1b59053332cdaa00c6a0d08b43f02fb2d12bf2749098b6d9d5eed693b39b695` | linux/arm64 |
| fixed | `rustfs/rustfs:1.0.0-alpha.94` | `sha256:7d49faa88c045af618a9ca6e1a9dc5b6cb87ea6fb407a682d825478e4001b40c` | linux/arm64 |

The digests are the ones Docker reports for the tags it pulled (`docker image inspect`). Docker
29.9.2 on an Apple Silicon Mac. Raw results: [`lab/rustfs/results/`](../../lab/rustfs/results)
(`meta.txt`, `oracle.tsv`, `rangeprobe.json`, `rangeprobe.html`, `rangeprobe.txt` per version).

## What the lab does

`lab/rustfs/run.sh` (requires Docker, Go, curl, cmp):

1. Builds `rangeprobe` and a minimal adapter, `lab/rustfs/main.go`. The adapter is a **separate Go
   module** with three functions: write a deterministic pseudo-random file, `PUT` it with a
   SigV4-signed request, print a presigned `GET` URL. It refuses non-loopback endpoints. RangeProbe
   itself has no S3 client.
2. Generates a 24 MiB file (seed 2506, sha256
   `42d65a939da63831a8dac71dbf28ca918d77b8617b3df2976423b8c7d2442b04`) that exists nowhere
   else, starts a container bound to `127.0.0.1` with a throwaway volume, uploads the file,
   and confirms a full `GET` returns identical bytes.
3. **Independent oracle**: requests the issue's pattern with `curl` (4 KiB at 0, 10, ..., 90 and 99
   percent, plus a 48 KiB tail) and compares each response with the matching slice of the local file
   using `tail`, `head` and `cmp`. RangeProbe is not involved.
4. Runs `rangeprobe reference <presigned-url> object.bin --probe-size 48KiB` on the same file.
5. Removes the containers, volumes and generated file.

Run it yourself:

```bash
lab/rustfs/run.sh                      # both versions
lab/rustfs/run.sh 1.0.0-alpha.93       # one version
```

The credentials are fixed throwaway values inside the script, used only by the disposable container.

## Result

The case reproduces on `1.0.0-alpha.93` and does not on `1.0.0-alpha.94`. Repeated runs of the script
gave the same outcome.

Independent oracle (status, bytes received, comparison with the local file):

| Range (4 KiB at) | alpha.93 | alpha.94 |
| --- | --- | --- |
| 0, 10, 20, 30, 40 percent | 206, 4096 bytes, match | 206, 4096 bytes, match |
| 50, 60, 70, 80, 90, 99 percent | 206, **0 bytes**, mismatch | 206, 4096 bytes, match |
| last 48 KiB | 206, **0 bytes**, mismatch | 206, 49152 bytes, match |

Full `GET`: identical on both. On alpha.93 the failure begins between 40 and 50 percent of the file,
consistent with the issue's report.

RangeProbe (`--probe-size 48KiB`):

| Check | alpha.93 | alpha.94 |
| --- | --- | --- |
| `first-byte`, `head`, `middle`, `reread`, `unsatisfiable` | pass | pass |
| `tail`, `suffix`, `open-ended`, `past-eof`, `overlap` | **violation** `BODY_TRUNCATED`: 206 with the right `Content-Range` and `Content-Length: 49152`, 0 bytes read | pass |
| exit code | 1 (problem) | 0 (pass) |

On alpha.93 the headers are correct and the body is empty. This is the class of failure that
header checks alone, or a full-file `GET`, would not catch.

## Reading the result honestly

- RangeProbe's `middle` probe passes on alpha.93 because it starts below the failing offset (it
  covers 12,558,336 to 12,607,487; the oracle's first failing 4 KiB range starts at 12,582,912).
  The defect was found by the probes that reach further into the file, among them `overlap`, which
  starts at 12,582,912. A single probe at the middle would not have been enough.
- The oracle and RangeProbe agree, and the oracle does not depend on RangeProbe's logic.
- The result says that these two images, on this platform, with this file and a default single-node
  setup, behave this way. It says nothing about other RustFS versions, drive layouts, object sizes
  or clients. That the fix in #2493 is the cause is inferred from the version boundary and the issue
  thread; it was not bisected here.
- The test objects are single-part uploads of one size. Multipart uploads (the issue mentions
  part-boundary alignment as a suspicion) were not tested.
- RustFS answers the `416` of the `unsatisfiable` check without a `Content-Range` header on both
  versions. RFC 9110 14.4 says a server SHOULD send one, so RangeProbe records the note
  `RANGE_416_CONTENT_RANGE_MISSING` and does not treat it as a violation.
- A first draft of the oracle reused a stale output file when `curl` received an empty body, which
  made the empty reads look like 4096 byte mismatches. The script now deletes the file before each
  request. The table above comes from the corrected script.
