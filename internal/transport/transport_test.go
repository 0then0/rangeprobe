package transport

import (
	"context"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/0then0/rangeprobe/internal/redact"
	"github.com/0then0/rangeprobe/internal/testsrv"
)

func newClient(h http.Header) *Client {
	return New(Config{Headers: h, RequestTimeout: 2 * time.Second, MaxRedirects: 3, Redactor: redact.New(true)})
}

func readAll(limit int64) (func(*Head) BodyPlan, *strings.Builder) {
	sb := &strings.Builder{}
	return func(*Head) BodyPlan { return BodyPlan{Limit: limit, Sink: sb} }, sb
}

func TestFetchSendsRangeAndIdentity(t *testing.T) {
	h := &testsrv.Handler{Data: testsrv.Content(1000)}
	srv := httptest.NewServer(h)
	defer srv.Close()
	dec, sb := readAll(1 << 20)
	ex := newClient(nil).Fetch(context.Background(), Request{URL: srv.URL, Range: "bytes=10-19"}, dec)
	if ex.Fail != nil || ex.Head.Status != 206 || ex.Read != 10 || !ex.EOF || sb.Len() != 10 {
		t.Fatalf("unexpected exchange: %+v read=%d", ex, ex.Read)
	}
	got := h.Requests()[0].Header
	if got.Get("Accept-Encoding") != "identity" || !strings.HasPrefix(got.Get("User-Agent"), "rangeprobe/") {
		t.Errorf("request headers: %v", got)
	}
}

func TestBodyLimitStopsReading(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		chunk := make([]byte, 1<<16)
		for i := 0; i < 1<<14; i++ { // up to 1 GiB; the client must stop long before
			if _, err := w.Write(chunk); err != nil {
				return
			}
		}
	}))
	defer srv.Close()
	dec, _ := readAll(100_000)
	ex := newClient(nil).Fetch(context.Background(), Request{URL: srv.URL}, dec)
	if ex.Read != 100_000 || ex.EOF || ex.BodyFail != nil {
		t.Fatalf("read=%d eof=%v fail=%v", ex.Read, ex.EOF, ex.BodyFail)
	}
}

func TestTruncatedBodyIsClassified(t *testing.T) {
	h := &testsrv.Handler{Data: testsrv.Content(1000), Tamper: func(r *testsrv.Reply) { r.CutAfter = 0 }}
	srv := httptest.NewServer(h)
	defer srv.Close()
	dec, _ := readAll(1 << 20)
	ex := newClient(nil).Fetch(context.Background(), Request{URL: srv.URL, Range: "bytes=0-9"}, dec)
	if ex.BodyFail == nil || ex.BodyFail.Kind != FailTruncated || ex.Read != 0 {
		t.Fatalf("want truncated, got %+v read=%d", ex.BodyFail, ex.Read)
	}
}

func TestRequestTimeout(t *testing.T) {
	h := &testsrv.Handler{Data: testsrv.Content(10), Tamper: func(r *testsrv.Reply) { r.Delay = time.Second }}
	srv := httptest.NewServer(h)
	defer srv.Close()
	c := New(Config{RequestTimeout: 100 * time.Millisecond, MaxRedirects: 3})
	dec, _ := readAll(10)
	start := time.Now()
	ex := c.Fetch(context.Background(), Request{URL: srv.URL}, dec)
	if ex.Fail == nil || ex.Fail.Kind != FailTimeout {
		t.Fatalf("want timeout, got %+v", ex.Fail)
	}
	if time.Since(start) > 800*time.Millisecond {
		t.Error("timeout not enforced promptly")
	}
}

func TestBodyStallTimesOut(t *testing.T) {
	h := &testsrv.Handler{Data: testsrv.Content(1000), Tamper: func(r *testsrv.Reply) { r.BodyDelay = 800 * time.Millisecond }}
	srv := httptest.NewServer(h)
	defer srv.Close()
	c := New(Config{RequestTimeout: 150 * time.Millisecond, MaxRedirects: 3})
	dec, _ := readAll(1000)
	ex := c.Fetch(context.Background(), Request{URL: srv.URL}, dec)
	if ex.BodyFail == nil || ex.BodyFail.Kind != FailTimeout {
		t.Fatalf("want body timeout, got fail=%+v body=%+v read=%d", ex.Fail, ex.BodyFail, ex.Read)
	}
}

func TestCancellation(t *testing.T) {
	h := &testsrv.Handler{Data: testsrv.Content(10), Tamper: func(r *testsrv.Reply) { r.Delay = 2 * time.Second }}
	srv := httptest.NewServer(h)
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)
	dec, _ := readAll(10)
	ex := newClient(nil).Fetch(ctx, Request{URL: srv.URL}, dec)
	if ex.Fail == nil || ex.Fail.Kind != FailCancelled {
		t.Fatalf("want cancelled, got %+v", ex.Fail)
	}
}

func TestRunDeadline(t *testing.T) {
	h := &testsrv.Handler{Data: testsrv.Content(10), Tamper: func(r *testsrv.Reply) { r.Delay = 2 * time.Second }}
	srv := httptest.NewServer(h)
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	dec, _ := readAll(10)
	ex := newClient(nil).Fetch(ctx, Request{URL: srv.URL}, dec)
	if ex.Fail == nil || ex.Fail.Kind != FailRunTimeout {
		t.Fatalf("want run timeout, got %+v", ex.Fail)
	}
}

func TestRedirectCrossOriginDropsCredentials(t *testing.T) {
	var got http.Header
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		w.Write([]byte("ok"))
	}))
	defer other.Close()
	var sameOrigin http.Header
	origin := httptest.NewServer(nil)
	defer origin.Close()
	mux := http.NewServeMux()
	mux.HandleFunc("/start", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/final?sig=1", http.StatusFound)
	})
	mux.HandleFunc("/hop", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/same", http.StatusFound) })
	mux.HandleFunc("/same", func(w http.ResponseWriter, r *http.Request) { sameOrigin = r.Header.Clone() })
	origin.Config.Handler = mux

	hdr := http.Header{"Authorization": {"Bearer s3cr3t"}, "X-Api-Key": {"k3y"}, "Cookie": {"a=b"}}
	dec, _ := readAll(10)
	ex := newClient(hdr).Fetch(context.Background(), Request{URL: origin.URL + "/start?token=zzz", Range: "bytes=0-1", IfMatch: `"v1"`}, dec)
	if ex.Fail != nil || len(ex.Hops) != 1 {
		t.Fatalf("fail=%+v hops=%+v", ex.Fail, ex.Hops)
	}
	for _, name := range []string{"Authorization", "X-Api-Key", "Cookie", "Referer", "If-Match"} {
		if got.Get(name) != "" {
			t.Errorf("%s leaked across origins: %q", name, got.Get(name))
		}
	}
	if got.Get("Range") != "bytes=0-1" {
		t.Errorf("Range must survive redirects, got %q", got.Get("Range"))
	}

	ex = newClient(hdr).Fetch(context.Background(), Request{URL: origin.URL + "/hop"}, dec)
	if ex.Fail != nil || sameOrigin.Get("Authorization") != "Bearer s3cr3t" || sameOrigin.Get("X-Api-Key") != "k3y" {
		t.Errorf("same-origin redirect must keep user headers: fail=%+v hdr=%v", ex.Fail, sameOrigin)
	}
	if sameOrigin.Get("Referer") != "" {
		t.Errorf("Referer must never be sent: %q", sameOrigin.Get("Referer"))
	}
	if ex.FinalURL != origin.URL+"/same" {
		t.Errorf("final url %q", ex.FinalURL)
	}
}

func TestRedirectLimit(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, srv.URL+"/again", http.StatusFound)
	}))
	defer srv.Close()
	dec, _ := readAll(1)
	ex := newClient(nil).Fetch(context.Background(), Request{URL: srv.URL}, dec)
	if ex.Fail == nil || ex.Fail.Kind != FailRedirectLimit {
		t.Fatalf("want redirect limit, got %+v", ex.Fail)
	}
	if len(ex.Hops) != 3 {
		t.Errorf("hops = %d, want 3", len(ex.Hops))
	}
}

func TestHTTPSToHTTPDowngradeRefused(t *testing.T) {
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("plain")) }))
	defer plain.Close()
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plain.URL, http.StatusFound)
	}))
	defer tlsSrv.Close()
	pool := x509.NewCertPool()
	pool.AddCert(tlsSrv.Certificate())
	c := New(Config{RequestTimeout: 2 * time.Second, MaxRedirects: 3, RootCAs: pool})
	dec, _ := readAll(10)
	ex := c.Fetch(context.Background(), Request{URL: tlsSrv.URL}, dec)
	if ex.Fail == nil || ex.Fail.Kind != FailRedirectRefused || !strings.Contains(ex.Fail.Message, "downgrade") {
		t.Fatalf("downgrade must be refused: %+v", ex.Fail)
	}
}

func TestTLSVerificationIsOn(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	dec, _ := readAll(10)
	ex := newClient(nil).Fetch(context.Background(), Request{URL: srv.URL}, dec)
	if ex.Fail == nil || ex.Fail.Kind != FailTLS {
		t.Fatalf("an untrusted certificate must fail verification: %+v", ex.Fail)
	}
}

func TestErrorMessagesAreRedacted(t *testing.T) {
	r := redact.New(true)
	c := New(Config{RequestTimeout: time.Second, MaxRedirects: 1, Redactor: r})
	dec, _ := readAll(1)
	ex := c.Fetch(context.Background(), Request{URL: "http://127.0.0.1:1/x?X-Amz-Signature=topsecret"}, dec)
	if ex.Fail == nil {
		t.Fatal("expected connection failure")
	}
	if strings.Contains(ex.Fail.Message, "topsecret") {
		t.Errorf("signature leaked: %s", ex.Fail.Message)
	}
}

func TestContentEncodingIsNotDecoded(t *testing.T) {
	gz := []byte{0x1f, 0x8b, 0x08, 0, 0, 0, 0, 0, 0, 0xff} // not valid gzip data on purpose
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		w.Write(gz)
	}))
	defer srv.Close()
	dec, sb := readAll(100)
	ex := newClient(nil).Fetch(context.Background(), Request{URL: srv.URL}, dec)
	if ex.Fail != nil || ex.BodyFail != nil || sb.String() != string(gz) {
		t.Fatalf("raw bytes must be delivered untouched: fail=%+v body=%v", ex.Fail, ex.BodyFail)
	}
	if ex.Head.Header.Get("Content-Encoding") != "gzip" {
		t.Error("Content-Encoding header must be preserved")
	}
}

var _ = io.EOF
