package cli

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/0then0/rangeprobe/internal/model"
)

// Exercise the installed-style command, argument parsing, process exit codes,
// exact raw validators and both report renderers over a real HTTP connection.
func TestIfRangePublicCLI(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "rangeprobe")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	build := exec.Command("go", "build", "-o", bin, "./cmd/rangeprobe")
	build.Dir = filepath.Join("..", "..")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	tag := `"` + strings.Repeat("x", 240) + `TAIL"`
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-Match") != "" {
			t.Error("If-Match on conditional resume request")
		}
		etag := tag
		switch r.URL.Path {
		case "/broken":
			r.Header.Del("If-Range")
		case "/ignore":
			r.Header.Del("Range")
		case "/weak":
			etag = `W/"a_weak_etag"`
		case "/none":
			etag = ""
		}
		if etag != "" {
			w.Header().Set("ETag", etag)
		}
		http.ServeContent(w, r, "fixture.bin", time.Time{}, bytes.NewReader([]byte("file content")))
	}))
	defer s.Close()
	for _, tc := range []struct {
		path  string
		extra []string
		code  int
	}{
		{"/good", nil, 0}, {"/broken", nil, 1}, {"/ignore", nil, 2}, {"/none", nil, 3},
		{"/weak", []string{"--weak-if-range"}, 3},
		{"/good", []string{"--max-requests", "1"}, 3},
		{"/good", []string{"--preconditions"}, 64},
		{"/good", []string{"-H", "rAnGe: bytes=0-0"}, 64},
		{"/good", []string{"-H", `If-Range: "user"`}, 64},
		{"/good", []string{"-H", `If-Match: "user"`}, 64},
		{"/good", []string{"-H", "If-Modified-Since: Sun, 06 Nov 1994 08:49:37 GMT"}, 64},
	} {
		t.Run(tc.path+strings.Join(tc.extra, " "), func(t *testing.T) {
			htmlPath := filepath.Join(t.TempDir(), "report.html")
			args := []string{"if-range", s.URL + tc.path + "?token=SECRET", "--probe-size", "5", "--json", "-", "--html", htmlPath}
			args = append(args, tc.extra...)
			cmd := exec.Command(bin, args...)
			var out, stderr bytes.Buffer
			cmd.Stdout = &out
			cmd.Stderr = &stderr
			err := cmd.Run()
			code := 0
			if ee, ok := err.(*exec.ExitError); ok {
				code = ee.ExitCode()
			} else if err != nil {
				t.Fatal(err)
			}
			if code != tc.code {
				t.Fatalf("exit %d want %d: %s %s", code, tc.code, &out, &stderr)
			}
			if code == 64 {
				if out.Len() != 0 {
					t.Fatal(&out)
				}
				return
			}
			var rep model.Report
			if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
				t.Fatalf("%v: %s", err, &out)
			}
			if rep.Run.Mode != "if-range" || rep.SchemaVersion != 1 || rep.IfRange == nil {
				t.Fatalf("%+v", rep)
			}
			html, err := os.ReadFile(htmlPath)
			if err != nil {
				t.Fatal(err)
			}
			for name, b := range map[string][]byte{"json": out.Bytes(), "html": html, "text": stderr.Bytes()} {
				if bytes.Contains(b, []byte("SECRET")) || !bytes.Contains(b, []byte("if-range-baseline")) {
					t.Fatalf("%s redaction/evidence: %s", name, b)
				}
			}
			if !bytes.Contains(html, []byte("Body evidence is separate")) || !bytes.Contains(stderr.Bytes(), []byte("If-Range evidence")) {
				t.Fatal("missing per-axis output")
			}
			if tc.path == "/good" && len(tc.extra) == 0 {
				e := rep.Checks[1].IfRange
				raw, err := base64.StdEncoding.DecodeString(e.ValidatorBase64)
				if err != nil || string(raw) != tag || !e.ValidatorSent || e.Outcome != "conditional_range_supported" {
					t.Fatalf("%+v %q %v", e, raw, err)
				}
				if strings.Contains(e.Validator, "TAIL") {
					t.Fatal("display was not truncated")
				}
				if !rep.Checks[2].Body.Complete || rep.Checks[2].Body.BytesRead != 12 || rep.Checks[2].IfRange.Outcome != "fallback_observed" {
					t.Fatal(rep.Checks[2])
				}
			}
			if tc.path == "/weak" && (!bytes.Contains(html, []byte("Deliberately invalid client input")) || rep.Checks[3].Response.Status != 200) {
				t.Fatal("missing weak evidence")
			}
		})
	}
}
