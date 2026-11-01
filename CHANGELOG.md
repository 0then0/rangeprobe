# Changelog

All notable changes are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/). Set the release date in the heading
before tagging; the release workflow refuses an undated heading.

## [0.1.0] - unreleased

First version.

### Added

- `rangeprobe reference URL FILE`: sends a bounded set of single-range requests and compares
  the response bytes with the matching slices of a local reference file, streaming, without
  loading the file into memory.
- `rangeprobe observe URL`: checks status and header consistency, body length against the
  declared length, and agreement of overlapping and repeated reads, without claiming that
  any bytes are correct.
- Ten checks: first byte, start, middle, end, suffix range, open-ended range, last-pos beyond
  EOF, unsatisfiable range, overlapping ranges, re-read.
- Findings with stable IDs, required conditions, concrete evidence and stated limits
  ([docs/diagnostics.md](docs/diagnostics.md)).
- A full `200` answer to a range request is reported as `range_ignored` (exit code 2), not as an
  RFC violation.
- Representation tracking: a changed strong ETag, length, Last-Modified or content coding
  makes the affected comparisons inconclusive instead of reporting a server defect.
- Hard limits on requests, total bytes, bytes per response, per-request and total time, and
  redirects. Large or endless responses are cut off at the limit.
- Redirect policy: bounded hops, no HTTPS to HTTP downgrade, user headers and `If-Match` dropped
  on cross-origin redirects, no `Referer`. TLS verification is always on.
- Text summary, versioned JSON report (schema 1) and standalone HTML report. URL query values,
  credentials and local directories are redacted by default. Reports are written atomically and
  never overwrite existing files without `--force`.
- Exit codes: 0 pass, 1 confirmed problem, 2 range ignored, 3 incomplete, 64 usage, 70 run error,
  130 interrupted.
- RustFS lab for [rustfs/rustfs#2506](https://github.com/rustfs/rustfs/issues/2506) in `lab/rustfs`
  with results ([docs/lab/rustfs-2506.md](docs/lab/rustfs-2506.md)).
- Release packaging for Linux, macOS and Windows (amd64, arm64) with `SHA256SUMS`.
