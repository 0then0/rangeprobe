package report

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/0then0/rangeprobe/internal/model"
)

const evil = `<script>alert(1)</script>"><img src=x onerror=alert(2)>` + "\u202e" + `javascript:alert(3)`

func sample() *model.Report {
	len20 := int64(20000)
	r := &model.Report{
		SchemaVersion: model.SchemaVersion,
		Tool:          model.ToolInfo{Name: "rangeprobe", Version: "0.1.0", Repository: "https://example.invalid/rangeprobe"},
		Run:           model.RunInfo{Mode: "reference", Target: "https://host.example/f?sig=REDACTED", Params: model.Params{RedactLocations: true, HeaderNames: []string{"X-Evil"}}},
		Reference:     &model.ReferenceInfo{Name: "ref.bin", Size: 20000},
		Endpoint:      model.EndpointInfo{FinalURL: "https://cdn.example/x?k=REDACTED"},
		Representation: model.RepresentationInfo{
			Length: &len20, LengthBasis: "content-range", ETag: `"a"`, ETagStrength: "strong", Stable: true,
		},
		Checks: []model.Check{{
			ID: "head", Title: "Range at the start", Key: true, Claim: "claim " + evil,
			Request: &model.RequestInfo{Method: "GET", URL: "u", Range: "bytes=0-9", Description: "GET https://host.example/f\nRange: bytes=0-9", Headers: []model.KV{{Key: "Range", Value: "bytes=0-9"}}},
			Response: &model.ResponseInfo{Status: 206, Proto: "HTTP/1.1", FinalURL: "x",
				Headers: []model.KV{{Key: "Content-Range", Value: "bytes 0-9/20000"}, {Key: "Server", Value: evil}}},
			Body: &model.BodyInfo{BytesRead: 10, EndState: "complete", Complete: true},
			Findings: []model.Finding{
				model.NewFinding("BODY_TRUNCATED", evil+"\x1b[31m", model.Ev("evidence", evil)).WithLimits("lim"),
			},
		}},
		Assumptions: []string{evil},
	}
	r.Checks[0].Finalize()
	r.Summarize()
	return r
}

func TestHTMLEscapesUntrustedStrings(t *testing.T) {
	out, err := HTML(sample())
	if err != nil {
		t.Fatal(err)
	}
	page := string(out)
	for _, bad := range []string{"<script>", "<img", `onerror=alert(2)>`} {
		if strings.Contains(page, bad) {
			t.Errorf("unescaped %q in page", bad)
		}
	}
	if !strings.Contains(page, "&lt;script&gt;") {
		t.Error("expected escaped markup in output")
	}
}

func TestHTMLIsSelfContained(t *testing.T) {
	out, err := HTML(sample())
	if err != nil {
		t.Fatal(err)
	}
	page := string(out)
	allowed := map[string]bool{"html": true, "head": true, "meta": true, "title": true, "style": true, "body": true, "main": true,
		"h1": true, "h2": true, "h4": true, "p": true, "span": true, "div": true, "dl": true, "dt": true, "dd": true, "code": true, "pre": true,
		"details": true, "summary": true, "ul": true, "li": true, "strong": true, "br": true, "footer": true}
	tag := regexp.MustCompile(`<\s*/?\s*([a-zA-Z][a-zA-Z0-9]*)([^>]*)>`)
	attr := regexp.MustCompile(`(?i)\b(href|src|srcset|action|formaction|xlink:href|on[a-z]+)\s*=`)
	// The CSS block and the doctype are static; only inspect markup outside <style>.
	body := regexp.MustCompile(`(?s)<style>.*?</style>`).ReplaceAllString(page, "")
	for _, m := range tag.FindAllStringSubmatch(body, -1) {
		if !allowed[strings.ToLower(m[1])] {
			t.Errorf("unexpected element <%s>", m[1])
		}
		if attr.MatchString(m[2]) {
			t.Errorf("active attribute in %q", m[0])
		}
	}
	if strings.Contains(page, "@import") || strings.Contains(page, "url(") {
		t.Error("external CSS reference")
	}
	if !strings.Contains(page, "default-src 'none'") {
		t.Error("CSP missing")
	}
	if !strings.Contains(page, "prefers-color-scheme") {
		t.Error("dark mode missing")
	}
}

func TestJSONIsVersionedAndStable(t *testing.T) {
	out, err := JSON(sample())
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if m["schema_version"] != float64(model.SchemaVersion) {
		t.Errorf("schema_version = %v", m["schema_version"])
	}
	for _, key := range []string{"tool", "run", "summary", "checks", "run_findings", "verified_claims", "unsupported", "uncertainty", "assumptions", "budget", "representation", "endpoint"} {
		if _, ok := m[key]; !ok {
			t.Errorf("missing top-level key %q", key)
		}
	}
	run := m["run"].(map[string]any)
	if _, ok := run["params"]; !ok {
		t.Error("run parameters missing")
	}
	if strings.Contains(string(out), `"Identity"`) || strings.Contains(string(out), "<script>") {
		t.Error("internal field or raw markup in JSON")
	}
	chk := m["checks"].([]any)[0].(map[string]any)
	f := chk["findings"].([]any)[0].(map[string]any)
	for _, k := range []string{"id", "kind", "message", "conditions", "evidence", "limits"} {
		if _, ok := f[k]; !ok {
			t.Errorf("finding lacks %q", k)
		}
	}
}

func TestTextShowsEvidenceAndLimits(t *testing.T) {
	var sb strings.Builder
	Text(&sb, sample())
	s := sb.String()
	if strings.Contains(s, "\u202e") || strings.Contains(s, "\x1b") {
		t.Error("control characters reached the terminal output")
	}
	for _, want := range []string{"RESULT: PROBLEM", "BODY_TRUNCATED", "requires:", "Assumptions", "Budget:", `\u202e`} {
		if !strings.Contains(s, want) {
			t.Errorf("text lacks %q:\n%s", want, s)
		}
	}
}

func TestWriteFileDoesNotOverwriteWithoutForce(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "r.json")
	if err := os.WriteFile(p, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := WriteFile(p, []byte("new"), false)
	if !errors.Is(err, ErrExists) {
		t.Fatalf("err = %v", err)
	}
	if b, _ := os.ReadFile(p); string(b) != "old" {
		t.Errorf("existing file modified: %q", b)
	}
	if err := WriteFile(p, []byte("new"), true); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(p); string(b) != "new" {
		t.Errorf("force did not replace: %q", b)
	}
	leftovers, _ := filepath.Glob(filepath.Join(dir, ".*tmp*"))
	if len(leftovers) != 0 {
		t.Errorf("temporary files left: %v", leftovers)
	}
}

func TestWriteFileNewAndNoPartialFiles(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "r.html")
	if err := WriteFile(p, []byte("data"), false); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(p); string(b) != "data" {
		t.Errorf("got %q", b)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("unexpected files: %v", entries)
	}
	if err := WriteFile(filepath.Join(dir, "missing", "r.json"), []byte("x"), false); err == nil {
		t.Error("writing into a missing directory must fail")
	}
}

func TestWriteFileRefusesSymlinkAndDirectory(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	os.WriteFile(target, []byte("keep"), 0o600)
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skip("symlinks unavailable")
	}
	if err := WriteFile(link, []byte("x"), true); err == nil {
		t.Error("must not replace a symlink")
	}
	if b, _ := os.ReadFile(target); string(b) != "keep" {
		t.Error("symlink target modified")
	}
	if err := WriteFile(dir, []byte("x"), true); err == nil {
		t.Error("must not replace a directory")
	}
}
