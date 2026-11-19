package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/0then0/rangeprobe/internal/model"
	"github.com/0then0/rangeprobe/internal/testsrv"
)

func TestMultipartCLI(t *testing.T) {
	data := testsrv.Content(256)
	copy(data, "TEST-BODY-SECRET")
	ref := filepath.Join(t.TempDir(), "fixture.bin")
	if err := os.WriteFile(ref, data, 0o600); err != nil {
		t.Fatal(err)
	}
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Range"); got != "bytes=128-143,0-15" {
			t.Errorf("Range = %q", got)
		}
		if got := r.Header.Get("Accept-Encoding"); got != "identity" {
			t.Errorf("Accept-Encoding = %q", got)
		}
		if r.Header.Get("Authorization") != "" {
			t.Error("Authorization forwarded to another origin")
		}
		http.ServeContent(w, r, "fixture.bin", time.Time{}, bytes.NewReader(data))
	}))
	t.Cleanup(destination.Close)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer TEST-HEADER-SECRET" {
			t.Error("missing Authorization on the original request")
		}
		// Leave the redirect body open. The client must follow from the headers
		// without waiting to drain any bytes from this hop.
		w.Header().Set("Location", destination.URL+"?token=TEST-REDIRECT-SECRET")
		w.WriteHeader(http.StatusFound)
		w.(http.Flusher).Flush()
		select {
		case <-r.Context().Done():
		case <-t.Context().Done():
		}
	}))
	t.Cleanup(origin.Close)

	target := origin.URL + "?token=TEST-URL-SECRET"
	flags := []string{
		"--range", "128-143", "--range", "0-15", "--reference", ref,
		"-H", "Authorization: Bearer ${TOKEN}", "--request-timeout", "2s", "--json", "-",
	}
	env := map[string]string{"TOKEN": "TEST-HEADER-SECRET"}
	orders := [][]string{
		append([]string{"multipart", target}, flags...),
		append(append([]string{"multipart"}, flags...), target),
	}
	for _, args := range orders {
		code, stdout, stderr := run(t, env, args...)
		var rep model.MultipartReport
		if err := json.Unmarshal([]byte(stdout), &rep); err != nil || code != model.ExitPass {
			t.Fatalf("exit %d\nstdout: %s\nstderr: %s", code, stdout, stderr)
		}
		if !strings.Contains(stderr, "RESULT: PASS") || !strings.Contains(stderr, "Multipart framing: valid") || !strings.Contains(stderr, "Part 2:") {
			t.Fatalf("wrong text summary: %s", stderr)
		}
		if rep.Mode != "multipart" || rep.Status != http.StatusPartialContent || rep.Range != "bytes=128-143,0-15" || len(rep.Parts) != 2 {
			t.Fatalf("wrong report: %s", stdout)
		}
		if strings.Contains(stdout+stderr, "SECRET") || strings.Contains(stdout+stderr, ref) {
			t.Fatal("report disclosed a secret or the full reference path")
		}
	}

	args := append([]string{"multipart", target}, flags...)
	code, stdout, stderr := run(t, env, append(args, "--max-bytes", "8B")...)
	var limited model.MultipartReport
	if err := json.Unmarshal([]byte(stdout), &limited); err != nil || code != model.ExitIncomplete {
		t.Fatalf("8B limit: exit %d\nstdout: %s\nstderr: %s", code, stdout, stderr)
	}
	if limited.BodyLimit != 8 || limited.BytesRead > 8 || limited.BodyComplete || limited.ObservationIssue == "" {
		t.Fatalf("missing read-limit evidence: %s", stdout)
	}
}

func TestMultipartCLIRedactsReflectedSecrets(t *testing.T) {
	const headerSecret = "private header literal"
	const querySecret = "private/query literal"
	escapedQuery := url.QueryEscape(querySecret)
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Header().Set("Location", "/"+url.PathEscape(r.Header.Get("X-Private"))+"?token="+escapedQuery)
			w.WriteHeader(http.StatusFound)
			return
		}
		w.Header().Set("Content-Range", querySecret+" "+escapedQuery)
		w.Header().Set("Content-Type", `application/octet-stream; profile="http://`+r.Host+`/`+url.PathEscape(headerSecret)+`"`)
		w.WriteHeader(http.StatusPartialContent)
	}))
	defer s.Close()
	ref := filepath.Join(t.TempDir(), "fixture.bin")
	if err := os.WriteFile(ref, testsrv.Content(32), 0o600); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := run(t, map[string]string{"TOKEN": headerSecret},
		"multipart", s.URL, "--range", "0-7", "--range", "16-23", "--reference", ref,
		"-H", "X-Private: ${TOKEN}", "--json", "-")
	var rep model.MultipartReport
	if err := json.Unmarshal([]byte(stdout), &rep); err != nil || code != model.ExitProblem ||
		len(rep.Endpoint.Redirects) != 1 || !strings.Contains(rep.Endpoint.FinalURL, "/REDACTED?token=REDACTED") ||
		!strings.Contains(rep.ContentRange, "REDACTED") || !strings.Contains(rep.ContentType, "/REDACTED") {
		t.Fatalf("missing redacted redirect/header evidence: exit=%d report=%+v error=%v", code, rep, err)
	}
	for _, secret := range []string{headerSecret, url.PathEscape(headerSecret), querySecret, escapedQuery} {
		if strings.Contains(stdout+stderr, secret) {
			t.Fatal("report disclosed a reflected query or header secret")
		}
	}
}

func TestMultipartCLIReportWriting(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusPartialContent) // Missing Content-Range produces a finding.
	}))
	defer s.Close()
	ref := filepath.Join(t.TempDir(), "fixture.bin")
	if err := os.WriteFile(ref, testsrv.Content(32), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	code := Run(t.Context(), []string{
		"multipart", s.URL, "--range", "0-7", "--range", "16-23", "--reference", ref, "--json", "-",
	}, &stdout, failingMultipartWriter{}, os.Getenv)
	var rep model.MultipartReport
	if err := json.Unmarshal(stdout.Bytes(), &rep); err != nil || code != model.ExitRunError || rep.ExitCode != model.ExitProblem {
		t.Fatalf("expected a successful JSON write and text output failure: exit=%d report=%+v error=%v", code, rep, err)
	}
	if len(rep.Findings) != 1 || rep.Findings[0].Conditions == nil || rep.Findings[0].Evidence == nil || rep.Findings[0].Limits == nil {
		t.Fatalf("finding fields must use JSON arrays: %s", stdout.Bytes())
	}
}

type failingMultipartWriter struct{}

func (failingMultipartWriter) Write([]byte) (int, error) { return 0, errors.New("test output failure") }

func TestMultipartCLIInvalidInputSendsNoRequest(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	ref := filepath.Join(t.TempDir(), "fixture.bin")
	if err := os.WriteFile(ref, testsrv.Content(256), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		flags []string
	}{
		{"missing reference", []string{"--range", "0-15", "--range", "128-143", "--reference", ""}},
		{"one range", []string{"--range", "0-15"}},
		{"three ranges", []string{"--range", "0-15", "--range", "128-143", "--range", "200-207"}},
		{"overlap", []string{"--range", "0-15", "--range", "15-31"}},
		{"adjacency", []string{"--range", "0-15", "--range", "16-31"}},
		{"past EOF", []string{"--range", "0-15", "--range", "250-256"}},
		{"open", []string{"--range", "0-", "--range", "128-143"}},
		{"suffix", []string{"--range", "-16", "--range", "128-143"}},
		{"descending", []string{"--range", "15-0", "--range", "128-143"}},
		{"overflow", []string{"--range", "0-9223372036854775808", "--range", "128-143"}},
		{"conditional header", []string{"--range", "0-15", "--range", "128-143", "-H", `If-None-Match: "etag"`}},
		{"reference overwrite", []string{"--range", "0-15", "--range", "128-143", "--json", ref, "--force"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := append([]string{"multipart", srv.URL, "--reference", ref}, tc.flags...)
			code, stdout, stderr := run(t, nil, args...)
			if code != model.ExitUsage || stdout != "" || stderr == "" {
				t.Fatalf("exit %d\nstdout: %s\nstderr: %s", code, stdout, stderr)
			}
		})
	}
	if got := requests.Load(); got != 0 {
		t.Fatalf("%d requests sent for invalid input", got)
	}
}
