package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/0then0/rangeprobe/internal/testsrv"
	"github.com/0then0/rangeprobe/internal/version"
)

func run(t *testing.T, env map[string]string, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errb bytes.Buffer
	code = Run(context.Background(), args, &out, &errb, func(k string) string { return env[k] })
	return code, out.String(), errb.String()
}

func server(t *testing.T) (*httptest.Server, string, []byte) {
	t.Helper()
	data := testsrv.Content(30000)
	srv := httptest.NewServer(&testsrv.Handler{Data: data, ETag: `"v1"`})
	t.Cleanup(srv.Close)
	ref := filepath.Join(t.TempDir(), "ref.bin")
	if err := os.WriteFile(ref, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return srv, ref, data
}

func TestReferenceRunWritesBothReports(t *testing.T) {
	srv, ref, _ := server(t)
	dir := t.TempDir()
	j, h := filepath.Join(dir, "r.json"), filepath.Join(dir, "r.html")
	code, stdout, stderr := run(t, nil, "reference", srv.URL+"/f?sig=ABC", ref, "--json", j, "--html", h, "--probe-size", "512")
	if code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "RESULT: PASS") || strings.Contains(stdout, "ABC") {
		t.Errorf("stdout:\n%s", stdout)
	}
	var m struct {
		SchemaVersion int `json:"schema_version"`
		Run           struct {
			Mode   string `json:"mode"`
			Target string `json:"target"`
			Params struct {
				ProbeSize int64 `json:"probe_size"`
			} `json:"params"`
		} `json:"run"`
	}
	b, _ := os.ReadFile(j)
	if err := json.Unmarshal(b, &m); err != nil || m.SchemaVersion != 1 || m.Run.Mode != "reference" || m.Run.Params.ProbeSize != 512 {
		t.Fatalf("json: %v %+v", err, m)
	}
	if strings.Contains(string(b), "ABC") || strings.Contains(string(b), ref) {
		t.Error("report leaks the signature or the local path")
	}
	if hb, _ := os.ReadFile(h); !strings.Contains(string(hb), "<!doctype html>") {
		t.Error("html report missing")
	}
}

func TestExistingReportIsNotOverwritten(t *testing.T) {
	srv, ref, _ := server(t)
	j := filepath.Join(t.TempDir(), "r.json")
	os.WriteFile(j, []byte("precious"), 0o600)
	code, _, stderr := run(t, nil, "reference", srv.URL, ref, "--json", j)
	if code != 64 || !strings.Contains(stderr, "already exists") {
		t.Errorf("code %d stderr %s", code, stderr)
	}
	if b, _ := os.ReadFile(j); string(b) != "precious" {
		t.Error("file modified")
	}
	if code, _, _ := run(t, nil, "reference", srv.URL, ref, "--json", j, "--force"); code != 0 {
		t.Errorf("force: %d", code)
	}
}

func TestReportCannotOverwriteReference(t *testing.T) {
	srv, ref, data := server(t)
	code, _, stderr := run(t, nil, "reference", srv.URL, ref, "--json", ref, "--force")
	if code != 64 || !strings.Contains(stderr, "reference file") {
		t.Errorf("code %d stderr %s", code, stderr)
	}
	if b, _ := os.ReadFile(ref); !bytes.Equal(b, data) {
		t.Error("reference was modified")
	}
}

func TestJSONToStdoutKeepsStdoutClean(t *testing.T) {
	srv, ref, _ := server(t)
	code, stdout, stderr := run(t, nil, "reference", srv.URL, ref, "--json", "-")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(stdout), &m); err != nil {
		t.Fatalf("stdout is not pure JSON: %v", err)
	}
	if !strings.Contains(stderr, "RESULT: PASS") {
		t.Error("text summary should go to stderr")
	}
}

func TestExitCodes(t *testing.T) {
	data := testsrv.Content(30000)
	ignore := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(data) }))
	defer ignore.Close()
	ref := filepath.Join(t.TempDir(), "ref.bin")
	os.WriteFile(ref, data, 0o600)
	if code, _, _ := run(t, nil, "reference", ignore.URL, ref, "-q"); code != 2 {
		t.Errorf("ignored: %d", code)
	}
	bad := append([]byte(nil), data...)
	bad[29000] ^= 1
	badRef := filepath.Join(t.TempDir(), "bad.bin")
	os.WriteFile(badRef, bad, 0o600)
	srv, _, _ := server(t)
	if code, out, _ := run(t, nil, "reference", srv.URL, badRef, "-q", "--json", "-"); code != 1 {
		t.Errorf("mismatch: %d\n%s", code, out)
	}
	if code, _, _ := run(t, nil, "observe", srv.URL, "--max-requests", "2", "-q"); code != 3 {
		t.Errorf("incomplete: %d", code)
	}
	if code, _, _ := run(t, nil, "observe", srv.URL, "-q"); code != 0 {
		t.Errorf("pass: %d", code)
	}
}

func TestUsageErrors(t *testing.T) {
	cases := [][]string{
		{},
		{"bogus"},
		{"observe"},
		{"observe", "ftp://x/y"},
		{"observe", "https://user:pw@host/x"},
		{"observe", "http:///nohost"},
		{"reference", "http://h/x"},
		{"reference", "http://h/x", "/does/not/exist"},
		{"observe", "http://h/x", "--max-requests", "0"},
		{"observe", "http://h/x", "--max-requests", "101"},
		{"observe", "http://h/x", "--probe-size", "10MiB"},
		{"observe", "http://h/x", "--max-bytes", "2GiB"},
		{"observe", "http://h/x", "--timeout", "0s"},
		{"observe", "http://h/x", "--dump-mismatch", "65"},
		{"observe", "http://h/x", "-H", "Range: bytes=0-1"},
		{"observe", "http://h/x", "-H", "no colon"},
		{"observe", "http://h/x", "-H", "X-A: ${NOT_SET}"},
		{"observe", "http://h/x", "--no-such-flag"},
	}
	for _, args := range cases {
		code, _, stderr := run(t, nil, args...)
		if code != 64 {
			t.Errorf("%v: exit %d (%s)", args, code, stderr)
		}
	}
}

func TestFlagsMayFollowArguments(t *testing.T) {
	srv, ref, _ := server(t)
	if code, _, stderr := run(t, nil, "reference", srv.URL, ref, "-q", "--max-requests", "20"); code != 0 {
		t.Errorf("exit %d: %s", code, stderr)
	}
	if code, _, _ := run(t, nil, "reference", "-q", srv.URL, "--max-requests", "20", ref); code != 0 {
		t.Errorf("interleaved: %d", code)
	}
}

func TestHeadersFromFlagEnvAndFile(t *testing.T) {
	var got http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		w.WriteHeader(404)
	}))
	defer srv.Close()
	hf := filepath.Join(t.TempDir(), "h.txt")
	os.WriteFile(hf, []byte("# comment\n\nX-From-File: filevalue\n"), 0o600)
	code, stdout, stderr := run(t, map[string]string{"TOK": "ENVSECRET"}, "observe", srv.URL, "-H", "Authorization: Bearer ${TOK}", "--header-file", hf, "--json", "-")
	if code != 3 {
		t.Fatalf("exit %d", code)
	}
	if got.Get("Authorization") != "Bearer ENVSECRET" || got.Get("X-From-File") != "filevalue" {
		t.Errorf("headers not sent: %v", got)
	}
	for _, s := range []string{stdout, stderr} {
		if strings.Contains(s, "ENVSECRET") || strings.Contains(s, "filevalue") {
			t.Error("header value leaked into output")
		}
	}
	if !strings.Contains(stdout, "X-From-File") {
		t.Error("header names should be listed")
	}
}

func TestHeaderFileMustBePrivate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions")
	}
	hf := filepath.Join(t.TempDir(), "h.txt")
	os.WriteFile(hf, []byte("X-A: b\n"), 0o644)
	os.Chmod(hf, 0o644)
	code, _, stderr := run(t, nil, "observe", "http://127.0.0.1:1/x", "--header-file", hf)
	if code != 64 || !strings.Contains(stderr, "chmod 600") {
		t.Errorf("code %d: %s", code, stderr)
	}
}

func TestParseSize(t *testing.T) {
	good := map[string]int64{"0": 0, "10": 10, "10B": 10, "4KiB": 4096, "2 MiB": 2 << 20, "1GiB": 1 << 30}
	for in, want := range good {
		if got, err := ParseSize(in); err != nil || got != want {
			t.Errorf("%q: %d %v", in, got, err)
		}
	}
	for _, in := range []string{"", "-1", "1TB", "abc", "9999999999999GiB", "1.5MiB"} {
		if _, err := ParseSize(in); err == nil {
			t.Errorf("%q should fail", in)
		}
	}
}

func TestVersionAndHelp(t *testing.T) {
	code, out, _ := run(t, nil, "version")
	if code != 0 || !strings.HasPrefix(out, "rangeprobe "+version.Version+" ") {
		t.Errorf("%d %q", code, out)
	}
	code, out, _ = run(t, nil, "help")
	if code != 0 || !strings.Contains(out, "Exit codes") {
		t.Errorf("help: %d", code)
	}
}

func TestMismatchReportsRenderEverywhere(t *testing.T) {
	srv, _, data := server(t)
	bad := append([]byte(nil), data...)
	bad[29000] ^= 1
	badRef := filepath.Join(t.TempDir(), "secret-name.bin")
	os.WriteFile(badRef, bad, 0o600)
	dir := t.TempDir()
	j, h := filepath.Join(dir, "r.json"), filepath.Join(dir, "r.html")
	code, stdout, _ := run(t, nil, "reference", srv.URL, badRef, "--json", j, "--html", h, "--dump-mismatch", "4")
	if code != 1 {
		t.Fatalf("exit %d", code)
	}
	page, _ := os.ReadFile(h)
	for _, want := range []string{"first difference at offset 29000", "BYTES_MISMATCH_REFERENCE", "Fragment at 29000", "different file or version"} {
		if !strings.Contains(string(page), want) {
			t.Errorf("html lacks %q", want)
		}
	}
	for _, want := range []string{"first_mismatch_offset", "expected_hex", "observed_sha256"} {
		if b, _ := os.ReadFile(j); !strings.Contains(string(b), want) {
			t.Errorf("json lacks %q", want)
		}
	}
	if !strings.Contains(stdout, "Pattern:") || strings.Contains(stdout, "secret-name") == false {
		// the base name is kept; only directories are redacted
		t.Errorf("text summary:\n%s", stdout)
	}
	if strings.Contains(stdout, filepath.Dir(badRef)) {
		t.Error("directory of the reference leaked")
	}
}

func TestHostileServerCannotInjectIntoOutputs(t *testing.T) {
	data := testsrv.Content(30000)
	h := &testsrv.Handler{Data: data, ETag: `"<img src=x onerror=alert(1)>"`}
	h.Tamper = func(r *testsrv.Reply) {
		r.Header.Set("Server", "<script>alert(1)</script>‮\u001b[31m")
		r.Header.Set("Via", "javascript:alert(2)")
	}
	srv := httptest.NewServer(h)
	defer srv.Close()
	dir := t.TempDir()
	j, hp := filepath.Join(dir, "r.json"), filepath.Join(dir, "r.html")
	_, stdout, _ := run(t, nil, "observe", srv.URL, "--json", j, "--html", hp)
	page, _ := os.ReadFile(hp)
	if strings.Contains(string(page), "<script>alert") || strings.Contains(string(page), "<img src=x") || strings.Contains(string(page), "‮") {
		t.Error("untrusted markup or bidi control in the HTML report")
	}
	if strings.Contains(stdout, "‮") || strings.Contains(stdout, "\x1b") {
		t.Error("control characters in the terminal summary")
	}
	b, _ := os.ReadFile(j)
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("JSON invalid: %v", err)
	}
	if strings.Contains(string(b), "‮") {
		t.Error("bidi control in JSON")
	}
}

func TestMissingReportDirectoryFailsBeforeProbing(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++ }))
	defer srv.Close()
	code, _, stderr := run(t, nil, "observe", srv.URL, "--json", filepath.Join(t.TempDir(), "no-such-dir", "r.json"))
	if code != 64 || hits != 0 || !strings.Contains(stderr, "does not exist") {
		t.Errorf("code %d, requests sent %d, stderr %s", code, hits, stderr)
	}
}
