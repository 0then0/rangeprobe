# Contributing

Thank you for helping. RangeProbe is deliberately small: one question ("can this file be read in
parts?"), a bounded set of requests, and honest reporting of what was and was not established.

## Ground rules

- Standard library only. A new dependency needs a concrete reason in the pull request.
- Every new verdict needs a stable ID in `internal/model/diagnostics.go` with its required
  conditions, evidence and limits. Do not report more than the evidence shows. When the RFC allows
  several behaviours, accept all of them.
- Keep the limits real. Nothing may read more than the configured budgets allow, and no code path may
  read a body without a limit.
- Reports must stay safe to publish: no secrets, no response bodies, escaped untrusted text.
- Out of scope for v0.1: load testing, multipart/byteranges, a full HTTP conformance suite,
  endpoint discovery, whole-file verification, telemetry.

## Setup

Go 1.27 or newer. No other tools are needed.

```bash
git clone https://github.com/0then0/rangeprobe.git
cd rangeprobe
go build ./...
```

## Before opening a pull request

```bash
gofmt -l .          # must print nothing
go vet ./...
go test ./...
go test -race ./...
go mod tidy -diff   # must print nothing
```

CI runs the same on Linux, macOS and Windows (the race detector on Linux and macOS).

Tests use local `httptest` servers and `internal/testsrv`, a small correct range server whose
replies a test alters to model one defect. Test data must differ at every offset (`testsrv.Content`
is pseudo-random), because an array of zeros hides offset errors. A behaviour change needs a test
that fails without it.

### Diagnostics

`docs/diagnostics.md` is generated from the registry. After adding or changing an ID run:

```bash
RANGEPROBE_UPDATE_DOCS=1 go test ./internal/model -run TestDiagnosticsDoc
```

and commit the result. The normal test fails if the file is out of date.

### Package layout

| Package | Role |
| --- | --- |
| `internal/plan` | Which checks to run; static skip reasons. No I/O. |
| `internal/transport` | `net/http` client: redirects, timeouts, bounded reads. Draws no conclusions. |
| `internal/capture` | Streaming sink: digest, bounded retention, byte comparison with the reference. |
| `internal/interpret` | Observations to findings; representation fingerprints. |
| `internal/probe` | Runs the plan under budgets and assembles the report. |
| `internal/report` | Text, JSON, HTML and safe file writing. |
| `internal/model` | Report types, diagnostics registry, exit codes. |
| `internal/cli` | Flags, input files, output. |
| `lab/rustfs` | Separate module: the RustFS lab. Not built by `go test ./...`. |

## The lab

`lab/rustfs/run.sh` needs Docker. It starts disposable RustFS containers on loopback, uploads a
file it generated, and compares RangeProbe with an independent `curl` and `cmp` oracle. It is not
part of the tests and nothing in the normal test run needs a network or Docker.

## Commits and pull requests

Use [Conventional Commits](https://www.conventionalcommits.org/) in English, for example
`fix(interpret): treat 416 without Content-Range as a note`. Describe the user-visible change in
`CHANGELOG.md` under the unreleased version.

## Releases

1. Set the date in the `## [x.y.z] - YYYY-MM-DD` heading of `CHANGELOG.md` and make sure
   `internal/version/version.go` has the same version.
2. `scripts/check-release.sh --tag vx.y.z` and `scripts/package.sh` pass locally.
3. Push the tag. The release workflow builds the archives and `SHA256SUMS` and creates a
   **draft** release. A maintainer reviews and publishes it by hand.

By contributing you agree that your work is licensed under the Apache License 2.0, like the project.
