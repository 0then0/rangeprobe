## What and why

<!-- The behaviour this changes and the reason. Link the issue if there is one. -->

## Checks

- [ ] `gofmt -l .` prints nothing, `go vet ./...` and `go test ./...` pass
- [ ] Behaviour changes have a test that fails without the change
- [ ] New or changed diagnostics are in `internal/model/diagnostics.go`, and `docs/diagnostics.md` was regenerated
- [ ] User-visible changes are in `CHANGELOG.md` under *Unreleased*
- [ ] No new dependency (or the need is explained above)
- [ ] No secrets, signed URLs or private data in the diff, logs or attached reports
