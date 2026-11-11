<p align="center">
  <img src="assets/rangeprobe.svg" width="128" height="128" alt="RangeProbe: a file with a highlighted byte range and a check mark">
</p>

# RangeProbe

[![CI](https://img.shields.io/github/actions/workflow/status/0then0/rangeprobe/ci.yml?branch=main&label=CI)](https://github.com/0then0/rangeprobe/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/github/license/0then0/rangeprobe)](LICENSE)
[![Go version](https://img.shields.io/github/go-mod/go-version/0then0/rangeprobe)](go.mod)
[![Dependencies: none](https://img.shields.io/badge/dependencies-standard%20library%20only-555555)](go.mod)

**Can this published file be read in parts?**

RangeProbe sends a small, bounded set of single-range HTTP requests to a URL you name, checks
the responses, and, when you have a local copy, compares the bytes it receives with the matching
slices of that copy.

It exists for failures like this: a full `GET` works, but reading the middle or the footer of the
file returns wrong or empty data. That breaks Parquet readers, video seeking and resumed downloads.
The motivating case is [rustfs/rustfs#2506](https://github.com/rustfs/rustfs/issues/2506),
reproduced in the [lab](docs/lab/rustfs-2506.md).

RangeProbe v0.2.0 is a CLI written in Go with no dependencies beyond the standard library, plus a static [browser page](#in-the-browser).

## Install

Requires Go 1.27 or newer to build from source:

```bash
git clone https://github.com/0then0/rangeprobe.git
cd rangeprobe
go build -trimpath -o rangeprobe ./cmd/rangeprobe
./rangeprobe version
```

Prebuilt archives for Linux, macOS and Windows (amd64 and arm64) are available in the
[v0.2.0 release](https://github.com/0then0/rangeprobe/releases/tag/v0.2.0).
See [Verifying a download](#verifying-a-download).

## Use

Reference mode compares response bytes with a local file:

```bash
rangeprobe reference https://example.com/data/file.parquet ./file.parquet
```

Observe mode needs only a URL:

```bash
rangeprobe observe https://example.com/data/file.parquet
```

Add reports with `--json` and `--html`, for example:

```bash
rangeprobe reference "$URL" ./file.parquet --json report.json --html report.html
```

Reference mode assumes that the local file is byte-identical to the file that is currently
published. RangeProbe cannot check that. A byte mismatch means "the bytes differ", not "the server
is broken": you may have named another file or another version. The report says so next to every
mismatch.

Observe mode cannot show that bytes are correct, because there is nothing to compare them with.
It checks that the server's answers agree with each other: status and headers, body length against
the declared length, and overlapping or repeated reads against one another.

### Conditional resume with If-Range

```sh
rangeprobe if-range https://example.com/file.bin --json report.json --html report.html
```

This separate mode sends the same bounded single byte range three times: baseline,
matching strong `If-Range`, and an independent random strong entity-tag intended to
mismatch. It never sends `If-Match`. `--preconditions` belongs to observe/reference:
`If-Match` can reject a changed representation with `412`, whereas `If-Range` tells
the server to ignore Range and send the current representation when the condition
is false ([RFC 9110 13.1.5](https://www.rfc-editor.org/rfc/rfc9110.html#section-13.1.5)).

The report separates conditional range support from mismatch fallback:

- Matching `206`: validates Content-Range, length and repeated bytes with the existing
  range interpreter. Byte identity requires one final resource and a shared strong
  ETag with no conflicting length or encoding signals. This shows consistency,
  not identity with an unseen original.
- Matching `200`: allowed because a server may ignore Range. Conditional resume
  support remains unproven; a usable validator with all ranges ignored exits 2.
- Mismatching `200`: observed fallback, with body completeness reported separately.
  At most 64 KiB is read, further limited by response and total byte budgets. An
  unread tail is `prefix`, never a server truncation or proof of full-file transfer.
- Mismatching `206`: violation only when the sent validator reached the final request
  and differs from the current response's complete strong ETag. Missing, weak or
  unusable current ETags leave the mismatch premise inconclusive. A random collision
  or an echoed request tag does not establish mismatch. `412`, `416`, redirects and
  transport failures never count as fallback.

Missing, weak, malformed, repeated or over-8000-octet baseline ETags make the main
validator checks unavailable. Long usable tags are sent and compared in full;
reports show a safe shortened form and preserve exact protocol octets as base64 in
JSON. ETags are scoped to a resource: a changed final URL, including query, prevents
cross-resource byte comparisons. Changed representation signals make those
comparisons inconclusive, not byte defects.

`--weak-if-range` adds a separate opt-in server conformance probe. It sends the exact
baseline weak ETag, or the weak form of a strong baseline tag. This is **deliberately
invalid client input**: clients MUST NOT generate weak If-Range. Strong comparison
must fail, so `206` violates the server contract and `200` is the expected fallback.
This is not an ordinary resume strategy. The already fixed historical
[Starlette #3567 reproduction](lab/starlette/README.md) records exact revisions,
commands, before/after observations and an independent HTTP byte oracle.

No HTTP-date validators, multipart ranges, whole-object download or browser UI are
included. Other conditional request headers are rejected in this mode. Existing
budgets, TLS verification, redaction and credential forwarding rules apply.

Exit codes retain their meanings: 1 confirmed defect; 3 unavailable/inconclusive
checks or transport failures; 2 allowed ignored Range with no missing evidence;
0 verified conditional ranges and observed mismatch fallback. Body coverage remains
an independent field even with exit 0. Unlike legacy modes, this new mode gives
incomplete evidence priority over allowed ignored Range. Old reports are unchanged.

### What it checks

Each check is one `GET` with one `Range`. Probe size defaults to 4 KiB.

| Check           | Request                           | What is tested                                              |
| --------------- | --------------------------------- | ----------------------------------------------------------- |
| `first-byte`*   | `bytes=0-0`                       | Discovery; `Content-Range`, length, first byte              |
| `head`*         | start of the file                 | Returned bytes and `Content-Range`                          |
| `middle`*       | around the half-way point         | Same                                                        |
| `tail`*         | last bytes, explicit offsets      | Same                                                        |
| `suffix`*       | `bytes=-N`                        | The last N bytes                                            |
| `open-ended`    | `bytes=X-` near the end           | Everything up to EOF, bounded volume                        |
| `past-eof`      | last-pos beyond EOF               | Clamped to the representation length                        |
| `unsatisfiable` | first-pos at EOF                  | `416` (or a full `200`); needs a length the server reported |
| `overlap`       | second range overlapping `middle` | Common bytes are identical                                  |
| `reread`        | `middle` again                    | Same bytes again                                            |

\* key checks: the ones random-access readers depend on. A PASS requires all of them to pass.

Checks that need information RangeProbe does not have are skipped with a stated reason, never
guessed. Examples: no length from the server or the reference, a request or byte budget that is
used up, or an offset that would overflow 63 bits.

### Example

A healthy server (abridged):

```text
RangeProbe 0.1.0, reference mode
Target:     http://127.0.0.1:18080/good?token=REDACTED
Reference: ref.bin, 1,048,576 bytes (assumed identical to the published file; not verified)
Length:     1,048,576 bytes (reported by the server: content-range)

RESULT: PASS (exit code 0)
  All key checks passed (10 pass). Content identity with an unseen original is not proven.

Checks
  first-byte     PASS  bytes=0-0              206 bytes 0-0/1048576              1 B read (complete)
  middle         PASS  bytes=522240-526335    206 bytes 522240-526335/1048576    4,096 B read (complete)
  tail           PASS  bytes=1044480-1048575  206 bytes 1044480-1048575/1048576  4,096 B read (complete)
  unsatisfiable  PASS  bytes=1048576-         416 bytes */1048576                33 B read (discarded)
```

RustFS `1.0.0-alpha.93`, where ranges past about half of the file come back with the right headers
and an empty body ([details](docs/lab/rustfs-2506.md)):

```text
RESULT: PROBLEM (exit code 1)
  Key checks not passed: tail, suffix

  tail           VIOLATION  bytes=25116672-25165823  206 bytes 25116672-25165823/25165824  0 B read (truncated)
  [BODY_TRUNCATED] tail (violation): the body ended before the declared length
      declared_length = 49152
      bytes_read = 0
      content_length = 49152
      limit: A proxy, load balancer or network fault can end a stream early as well; repeat the run to see whether it is deterministic.
```

## In the browser

[`web/`](web) is a static page that runs the key checks from a browser, which shows what a *page*
can read: CORS-hidden headers, automatic content decoding and `fetch()` errors without a cause. It
compares the received bytes with slices of a local file, keeps the byte result and the header
evidence apart, and saves a JSON report. Requests go straight from the browser to your URL; nothing
is uploaded. See [docs/browser.md](docs/browser.md) for use, limits, a local two-origin lab and
hosting.

```bash
go run ./lab/browser -write-reference /tmp/reference.bin   # then open http://localhost:18080
```

## Results and exit codes

| Code | Result        | Meaning                                                                                                                                                         |
| ---- | ------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0    | pass          | Every key check passed and nothing was found wrong. Identity with an original is still not proven in observe mode.                                              |
| 1    | problem       | A protocol violation or a byte mismatch with the reference was found.                                                                                           |
| 2    | range ignored | The server answered range requests with full `200` responses. Random access is unavailable. This is allowed by RFC 9110 and is **not** reported as a violation. |
| 3    | incomplete    | No confirmed problem, but some checks were inconclusive, skipped or failed (transport error, budget, changed representation, unsupported encoding). Not a PASS. |
| 64   | usage         | Invalid command line or input file.                                                                                                                             |
| 70   | run error     | The run or writing a report failed.                                                                                                                             |
| 130  | interrupted   | Cancelled by a signal before completion.                                                                                                                        |

A check ends in one of these states: `pass`, `range_ignored`, `violation`, `byte_mismatch`,
`inconclusive`, `transport_error` or `skipped`. A run with a skipped key check never exits with 0.

Every finding has a stable ID, the conditions it needs, concrete evidence and the limits of what it
proves. See [docs/diagnostics.md](docs/diagnostics.md).

### Changed files are not server defects

RangeProbe records ETag, complete length, Last-Modified and content coding from every response.
If a strong ETag, a length or another signal changes during the run, the affected comparisons
become `inconclusive` instead of `byte_mismatch`. Equal Last-Modified values or the absence of
changes do not prove that the content is unchanged; without a shared strong ETag, differing bytes
between two reads are `inconclusive`, not a violation. `--preconditions` additionally sends
`If-Match` with the first strong ETag, so a replaced file fails with `412` instead of silently
returning other bytes.

## Limits

Every run has finite limits. Defaults, with the flag that changes each:

| Limit                                | Default           | Flag                   |
| ------------------------------------ | ----------------- | ---------------------- |
| Requests                             | 16 (max 100)      | `--max-requests`       |
| Body bytes over the whole run        | 8 MiB (max 1 GiB) | `--max-bytes`          |
| Body bytes of one response           | 2 MiB             | `--max-response-bytes` |
| Sampled range length                 | 4 KiB             | `--probe-size`         |
| Time per request, including its body | 30 s              | `--request-timeout`    |
| Time for the whole run               | 2 min             | `--timeout`            |
| Redirects per request                | 5 (max 20)        | `--max-redirects`      |

Requests are sequential and never retried. Only body bytes count toward the byte budget.
If a server answers a tiny range with a huge full response, RangeProbe reads at most 64 KiB of it
for a sanity comparison, stops, and reports what it could and could not establish. Ctrl-C and
SIGTERM stop the run, close open bodies and still write the reports.

## Privacy and credentials

- Only the URL you give is requested. There is no scanning or URL guessing. Local addresses are fine.
- TLS verification is always on and cannot be switched off. For a private CA use `--ca-file`.
- Redirects: bounded, never from HTTPS to HTTP, never to credentials in the URL. Your `-H` headers
  and `If-Match`/`If-Range` are sent only to the exact origin you named (scheme, host and port) and are
  dropped on any other origin. RangeProbe never adds a `Referer` and removes any on redirects.
- Send headers with `-H 'Authorization: Bearer ${TOKEN}'` (single quotes; `${VAR}` is read from the
  environment) or with `--header-file` (one `Name: value` per line; must not be readable by other
  users). Values given literally on the command line are visible in the process list.
- Header values are never written to reports; only header names are. The reproduction block in each
  check shows `REDACTED` for them and contains no shell command.
- By default reports replace URL query values with `REDACTED`, drop userinfo and fragments, and show
  only the base name of the reference file. `--no-redact` turns this off for URLs and paths.
- Reports never contain response bodies. For a mismatch they hold offsets, lengths and SHA-256
  digests. `--dump-mismatch N` (at most 64) adds a hex fragment and prints a warning, because the
  fragment is file content.
- The HTML report has no scripts, no external resources and no links. Untrusted headers, URLs and
  messages are escaped, and control and bidirectional characters are made visible.
- Report files are written to a temporary file and moved into place, so a partial report never
  looks finished. An existing file is not replaced without `--force`; symbolic links and
  directories are never replaced, and a report cannot overwrite the reference file.

## Reports

- Text summary on standard output (`-q` hides it). With `--json -` it goes to standard error and
  standard output carries only the JSON.
- `--json PATH`: versioned JSON, schema version 1, see [docs/report-format.md](docs/report-format.md).
  It records the app version and all run parameters.
- `--html PATH`: one standalone file, readable offline.

For each check the reports show what was requested, what the server returned, how many bytes were
actually read, the claim that was tested, the result, and the limits of that result. They also
list verified claims, unsupported capabilities and reasons for uncertainty separately.

## Protocol notes

The choices behind the checks, with the RFC 9110 sections they rest on, are in
[docs/protocol-notes.md](docs/protocol-notes.md). The main ones:

- A server may ignore `Range`; `200` instead of `206` is not a violation.
- `Accept-Ranges` is advice. Its absence does not prove missing support and its presence does not
  prove correctness. It is recorded as evidence, not used as a gate.
- `Content-Range` bounds are inclusive, and a last-pos beyond EOF is clamped.
- `Accept-Encoding: identity` is requested and transparent decompression is off. Range offsets
  address the encoded bytes (RFC 9110, 14.1.2), so a response with another content coding is not
  compared with the reference.
- `HEAD` is never required. `Content-Length` may be absent.
- Weak ETags are never used to confirm identity.

## Not in v0.1

Load testing or concurrency; a full HTTP conformance suite or `If-Range` conformance;
`multipart/byteranges` (a multipart answer to a single-range request is reported as unsupported
and not parsed); cache-poisoning or security scanning; endpoint discovery; checking a whole file
through many probes; accounts or telemetry. The browser page runs the key checks only and needs
no server.

## Verifying a download

Release archives are named `rangeprobe_<version>_<os>_<arch>.tar.gz` (`.zip` for Windows) and
come with a `SHA256SUMS` file. Download both into one directory.

Linux:

```bash
sha256sum --ignore-missing -c SHA256SUMS
```

macOS:

```bash
grep rangeprobe_0.1.0_darwin_arm64.tar.gz SHA256SUMS | shasum -a 256 -c -
```

Windows (PowerShell): compare the output of
`(Get-FileHash .\rangeprobe_0.1.0_windows_amd64.zip -Algorithm SHA256).Hash` with the matching
line of `SHA256SUMS`.

The checksum file lives next to the archives, so it protects against corrupted downloads, not
against a compromised release. The releases are built by the
[release workflow](.github/workflows/release.yml) from a tag; you can rebuild with
`scripts/package.sh` and compare.

## Development

```bash
go vet ./...
go test ./...
go test -race ./...
gofmt -l .
```

See [CONTRIBUTING.md](CONTRIBUTING.md). Security reports: [SECURITY.md](SECURITY.md).

The lab for the RustFS case needs Docker and is not part of the normal tests:
`lab/rustfs/run.sh`. See [docs/lab/rustfs-2506.md](docs/lab/rustfs-2506.md).

## License

Apache License 2.0, see [LICENSE](LICENSE). RangeProbe has no third-party Go dependencies; the
module's `go.mod` lists none. Test data is generated by the tests and the lab; nothing third-party
is bundled. RustFS container images are pulled by the lab script only when you run it and are
not distributed here (RustFS is also Apache-2.0).
