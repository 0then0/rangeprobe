package model

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// generatedDiagnostics renders docs/diagnostics.md from the registry so the
// documentation cannot drift from the code. Regenerate with
//
//	RANGEPROBE_UPDATE_DOCS=1 go test ./internal/model -run TestDiagnosticsDoc
func generatedDiagnostics() string {
	var b strings.Builder
	b.WriteString(`# Diagnostics

<!-- Generated from internal/model/diagnostics.go. Do not edit by hand:
     RANGEPROBE_UPDATE_DOCS=1 go test ./internal/model -run TestDiagnosticsDoc -->

Every finding in a report carries a stable ID, the conditions that must hold for
it to apply, concrete evidence from the exchange, and the limits of what it
proves. IDs do not change within a major version; new IDs may be added.

A check's status is the most significant kind among its findings, in this order:
` + "`violation`, `byte_mismatch`, `transport_error`, `inconclusive`, `range_ignored`, `pass`" + `.
Notes never change a status. A skipped check carries a skip reason ID instead of a finding.

`)
	groups := []struct {
		kind  Kind
		title string
		intro string
	}{
		{KindViolation, "Protocol-contract violations", "The response contradicts RFC 9110 or contradicts itself. Exit code 1."},
		{KindByteMismatch, "Byte mismatch with the reference", "An observation, not a diagnosis: the reference may be another file or version. Exit code 1."},
		{KindRangeIgnored, "Range ignored", "Allowed by RFC 9110 section 14.2, but incompatible with random access. Not a violation. Exit code 2."},
		{KindInconclusive, "Inconclusive", "The evidence does not support a verdict. Exit code 3 unless a confirmed problem exists."},
		{KindTransportError, "Transport and infrastructure errors", "The probe could not complete. Exit code 3 unless a confirmed problem exists."},
		{KindNote, "Notes", "Context that never changes a status."},
		{KindSkipped, "Skip reasons", "The check was not sent. A skipped key check prevents a complete PASS (exit code 3)."},
	}
	for _, g := range groups {
		fmt.Fprintf(&b, "## %s\n\n%s\n\n", g.title, g.intro)
		var ids []string
		for id, info := range Registry {
			if info.Kind == g.kind {
				ids = append(ids, id)
			}
		}
		sort.Strings(ids)
		for _, id := range ids {
			info := Registry[id]
			fmt.Fprintf(&b, "### `%s`\n\n%s.\n\n", id, strings.ToUpper(info.Title[:1])+info.Title[1:])
			if BrowserOnly[id] {
				b.WriteString("Emitted only by the browser page, never by the CLI.\n\n")
			}
			if len(info.Conditions) > 0 {
				b.WriteString("Requires:\n\n")
				for _, c := range info.Conditions {
					fmt.Fprintf(&b, "- %s\n", c)
				}
				b.WriteString("\n")
			}
		}
	}
	return b.String()
}

func TestDiagnosticsDoc(t *testing.T) {
	path := filepath.Join("..", "..", "docs", "diagnostics.md")
	want := generatedDiagnostics()
	if os.Getenv("RANGEPROBE_UPDATE_DOCS") != "" {
		if err := os.WriteFile(path, []byte(want), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Error("docs/diagnostics.md is out of date; run: RANGEPROBE_UPDATE_DOCS=1 go test ./internal/model -run TestDiagnosticsDoc")
	}
}

func TestRegistryIsConsistent(t *testing.T) {
	for id, info := range Registry {
		if id != strings.ToUpper(id) || strings.ContainsAny(id, " -") {
			t.Errorf("%s: IDs are UPPER_SNAKE_CASE", id)
		}
		if info.Title == "" {
			t.Errorf("%s: no title", id)
		}
		if info.Kind != KindSkipped && len(info.Conditions) == 0 {
			t.Errorf("%s: a diagnostic needs conditions", id)
		}
		if info.Kind == KindSkipped && !strings.HasPrefix(id, "SKIP_") {
			t.Errorf("%s: skip reasons start with SKIP_", id)
		}
		if info.Kind != KindSkipped && strings.HasPrefix(id, "SKIP_") {
			t.Errorf("%s: only skip reasons start with SKIP_", id)
		}
	}
}

func TestBrowserOnlyIDsAreRegistered(t *testing.T) {
	for id := range BrowserOnly {
		if _, ok := Registry[id]; !ok {
			t.Errorf("%s is listed as browser-only but not registered", id)
		}
	}
}

func TestStatusPriority(t *testing.T) {
	c := Check{Findings: []Finding{
		NewFinding("RANGE_IGNORED", "x"),
		NewFinding("PARTIAL_RESPONSE", "n"),
		NewFinding("CONTENT_RANGE_INVALID", "v"),
		NewFinding("REQUEST_FAILED", "t"),
	}}
	c.Verified = []string{"claim"}
	c.Finalize()
	if c.Status != KindViolation || c.Verified != nil {
		t.Errorf("status %s verified %v", c.Status, c.Verified)
	}
	c = Check{Findings: []Finding{NewFinding("PARTIAL_RESPONSE", "n")}}
	c.Finalize()
	if c.Status != KindPass {
		t.Errorf("a note must not change status: %s", c.Status)
	}
	c = Check{Skip: &Skip{ID: "SKIP_BUDGET_BYTES"}}
	c.Finalize()
	if c.Status != KindSkipped {
		t.Error("skipped")
	}
}

func rep(statuses map[string]Status, keys ...string) *Report {
	r := &Report{}
	isKey := map[string]bool{}
	for _, k := range keys {
		isKey[k] = true
	}
	ids := make([]string, 0, len(statuses))
	for id := range statuses {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		r.Checks = append(r.Checks, Check{ID: id, Key: isKey[id], Status: statuses[id]})
	}
	return r
}

func TestSummarizeExitCodes(t *testing.T) {
	cases := []struct {
		name string
		r    *Report
		want int
	}{
		{"all pass", rep(map[string]Status{"a": KindPass, "b": KindPass}, "a"), ExitPass},
		{"skipped optional still passes", rep(map[string]Status{"a": KindPass, "z": KindSkipped}, "a"), ExitPass},
		{"skipped key is not a pass", rep(map[string]Status{"a": KindSkipped, "b": KindPass}, "a"), ExitIncomplete},
		{"inconclusive optional is not a pass", rep(map[string]Status{"a": KindPass, "z": KindInconclusive}, "a"), ExitIncomplete},
		{"transport error", rep(map[string]Status{"a": KindTransportError}, "a"), ExitIncomplete},
		{"range ignored beats incomplete", rep(map[string]Status{"a": KindRangeIgnored, "b": KindInconclusive}, "a"), ExitRangeIgnored},
		{"violation beats everything", rep(map[string]Status{"a": KindViolation, "b": KindRangeIgnored, "c": KindInconclusive}, "a"), ExitProblem},
		{"byte mismatch", rep(map[string]Status{"a": KindByteMismatch}, "a"), ExitProblem},
	}
	for _, c := range cases {
		c.r.Summarize()
		if c.r.Summary.ExitCode != c.want {
			t.Errorf("%s: exit %d, want %d (%s)", c.name, c.r.Summary.ExitCode, c.want, c.r.Summary.Result)
		}
	}
	r := rep(map[string]Status{"a": KindPass}, "a")
	r.RunFindings = []Finding{NewFinding("REFERENCE_CHANGED", "x")}
	r.Summarize()
	if r.Summary.ExitCode != ExitIncomplete {
		t.Error("a run-level inconclusive finding must prevent PASS")
	}
}
