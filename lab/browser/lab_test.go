package main

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/0then0/rangeprobe/internal/testsrv"
)

const (
	pageOrigin = "http://localhost:18080"
	dataOrigin = "http://127.0.0.1:18081"
)

func testLab(t *testing.T) (l *lab, data, page *httptest.Server) {
	t.Helper()
	l = newLab(config{PageOrigin: pageOrigin, DataOrigin: dataOrigin, WebDir: "../../web", Size: 10_000, LargeSize: 64 << 20, Slow: 5 * time.Second})
	data = httptest.NewServer(l.dataHandler())
	page = httptest.NewServer(l.pageHandler())
	t.Cleanup(data.Close)
	t.Cleanup(page.Close)
	return
}

func get(t *testing.T, url, rng, origin string) (*http.Response, []byte) {
	t.Helper()
	req, _ := http.NewRequest("GET", url, nil)
	if rng != "" {
		req.Header.Set("Range", rng)
	}
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	req.Header.Set("Accept-Encoding", "identity")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, b
}

func TestOKRouteExposesEverything(t *testing.T) {
	l, data, _ := testLab(t)
	resp, body := get(t, data.URL+"/ok", "bytes=100-199", pageOrigin)
	if resp.StatusCode != 206 || !bytes.Equal(body, l.data[100:200]) {
		t.Fatalf("status %d, %d bytes", resp.StatusCode, len(body))
	}
	if resp.Header.Get("Access-Control-Allow-Origin") != pageOrigin {
		t.Error("the page's origin must be allowed")
	}
	for _, h := range []string{"Content-Range", "Accept-Ranges", "ETag", "Content-Encoding"} {
		if !strings.Contains(resp.Header.Get("Access-Control-Expose-Headers"), h) {
			t.Errorf("%s not exposed", h)
		}
	}
	if resp.Header.Get("Content-Range") != "bytes 100-199/10000" {
		t.Errorf("Content-Range %q", resp.Header.Get("Content-Range"))
	}
}

func TestOtherOriginsAreNotAllowed(t *testing.T) {
	_, data, _ := testLab(t)
	resp, _ := get(t, data.URL+"/ok", "bytes=0-0", "http://evil.example")
	if resp.Header.Get("Access-Control-Allow-Origin") != "" {
		t.Error("only the page origin may be allowed")
	}
}

func TestHiddenContentRangeIsSentButNotExposed(t *testing.T) {
	l, data, _ := testLab(t)
	resp, body := get(t, data.URL+"/hidden-content-range", "bytes=100-199", pageOrigin)
	if resp.Header.Get("Content-Range") == "" || !bytes.Equal(body, l.data[100:200]) {
		t.Fatal("the server answers correctly and sends Content-Range")
	}
	if resp.Header.Get("Access-Control-Allow-Origin") == "" {
		t.Error("the page must be allowed to read the response")
	}
	if strings.Contains(resp.Header.Get("Access-Control-Expose-Headers"), "Content-Range") {
		t.Error("Content-Range must not be exposed")
	}
}

func TestNoCORSRouteSendsNoCORSHeaders(t *testing.T) {
	_, data, _ := testLab(t)
	resp, _ := get(t, data.URL+"/no-cors", "bytes=0-9", pageOrigin)
	if resp.StatusCode != 206 {
		t.Fatalf("the server still answers: %d", resp.StatusCode)
	}
	for k := range resp.Header {
		if strings.HasPrefix(k, "Access-Control-") {
			t.Errorf("unexpected %s", k)
		}
	}
}

func TestPreflightAllowsRangeOnlyWhereCORSIsAllowed(t *testing.T) {
	_, data, _ := testLab(t)
	for route, allowed := range map[string]bool{"ok": true, "hidden-content-range": true, "no-cors": false} {
		req, _ := http.NewRequest("OPTIONS", data.URL+"/"+route, nil)
		req.Header.Set("Origin", pageOrigin)
		req.Header.Set("Access-Control-Request-Method", "GET")
		req.Header.Set("Access-Control-Request-Headers", "range")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		got := resp.Header.Get("Access-Control-Allow-Headers") == "Range" && resp.Header.Get("Access-Control-Allow-Origin") == pageOrigin
		if got != allowed {
			t.Errorf("%s: preflight allowed = %v, want %v", route, got, allowed)
		}
	}
}

func TestWrongBytesKeepHeadersAndLength(t *testing.T) {
	l, data, _ := testLab(t)
	resp, body := get(t, data.URL+"/wrong-bytes", "bytes=100-199", pageOrigin)
	if resp.StatusCode != 206 || resp.Header.Get("Content-Range") != "bytes 100-199/10000" || len(body) != 100 {
		t.Fatalf("headers must look right: %d %q %d", resp.StatusCode, resp.Header.Get("Content-Range"), len(body))
	}
	if !bytes.Equal(body, l.data[101:201]) || bytes.Equal(body, l.data[100:200]) {
		t.Error("the body must be the next 100 bytes")
	}
}

func TestRangeIgnoredSendsTheWholeFile(t *testing.T) {
	l, data, _ := testLab(t)
	resp, body := get(t, data.URL+"/range-ignored", "bytes=100-199", pageOrigin)
	if resp.StatusCode != 200 || !bytes.Equal(body, l.data) || resp.Header.Get("Content-Range") != "" {
		t.Fatalf("status %d, %d bytes", resp.StatusCode, len(body))
	}
}

func rawGet(t *testing.T, url, rng string) (*http.Response, []byte) {
	t.Helper()
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Range", rng)
	req.Header.Set("Origin", pageOrigin)
	resp, err := (&http.Transport{DisableCompression: true}).RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp, raw
}

func gunzip(t *testing.T, raw []byte) []byte {
	t.Helper()
	zr, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	plain, _ := io.ReadAll(zr)
	return plain
}

func TestEncodedRouteSendsTheWholeFileGzipped(t *testing.T) {
	l, data, _ := testLab(t)
	resp, raw := rawGet(t, data.URL+"/encoded", "bytes=100-199")
	if resp.StatusCode != 200 || resp.Header.Get("Content-Encoding") != "gzip" || resp.Header.Get("Content-Range") != "" {
		t.Fatalf("status %d, encoding %q", resp.StatusCode, resp.Header.Get("Content-Encoding"))
	}
	if !bytes.Equal(gunzip(t, raw), l.data) {
		t.Error("decoded body differs")
	}
}

func TestSlowHeadersStall(t *testing.T) {
	l := newLab(config{PageOrigin: pageOrigin, DataOrigin: dataOrigin, WebDir: "../../web", Size: 100, LargeSize: 1 << 20, Slow: 300 * time.Millisecond})
	srv := httptest.NewServer(l.dataHandler())
	defer srv.Close()
	start := time.Now()
	get(t, srv.URL+"/slow-headers", "bytes=0-9", pageOrigin)
	if time.Since(start) < 250*time.Millisecond {
		t.Errorf("headers arrived after %s", time.Since(start))
	}
}

// A client that reads a little and hangs up must stop the full response,
// and the counters must say so.
func TestLargeResponseStopsWhenTheClientLeaves(t *testing.T) {
	_, data, _ := testLab(t)
	req, _ := http.NewRequest("GET", data.URL+"/range-ignored-large", nil)
	req.Header.Set("Range", "bytes=0-0")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 || resp.ContentLength != 64<<20 {
		t.Fatalf("status %d, length %d", resp.StatusCode, resp.ContentLength)
	}
	first := make([]byte, 64<<10)
	if _, err := io.ReadFull(resp.Body, first); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first[:1000], testsrv.Content(10_000)[:1000]) {
		t.Error("the stream starts with the reference")
	}
	resp.Body.Close()
	var st struct {
		Routes map[string]routeStats `json:"routes"`
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		_, b := get(t, data.URL+"/__stats", "", "")
		if err := json.Unmarshal(b, &st); err != nil {
			t.Fatal(err)
		}
		if st.Routes["range-ignored-large"].Aborted > 0 || time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	got := st.Routes["range-ignored-large"]
	if got.Aborted != 1 || got.Completed != 0 || got.BytesWritten >= 8<<20 {
		t.Errorf("aborted=%d completed=%d written=%d", got.Aborted, got.Completed, got.BytesWritten)
	}
}

func TestSameOriginCopyHasNoCORSAndReferenceMatches(t *testing.T) {
	l, _, page := testLab(t)
	resp, body := get(t, page.URL+"/data/hidden-content-range", "bytes=0-9", "")
	if resp.StatusCode != 206 || !bytes.Equal(body, l.data[:10]) || resp.Header.Get("Access-Control-Allow-Origin") != "" {
		t.Errorf("same-origin copy: %d, ACAO %q", resp.StatusCode, resp.Header.Get("Access-Control-Allow-Origin"))
	}
	_, ref := get(t, page.URL+"/reference.bin", "", "")
	if !bytes.Equal(ref, testsrv.Content(10_000)) {
		t.Error("reference.bin must be the file the routes serve")
	}
	resp, body = get(t, page.URL+"/", "", "")
	if resp.StatusCode != 200 || !bytes.Contains(body, []byte("RangeProbe")) || resp.Header.Get("Cache-Control") != "no-store" {
		t.Error("the page must be served uncached")
	}
}

func TestStatsCountRequestsPreflightsAndRanges(t *testing.T) {
	_, data, _ := testLab(t)
	get(t, data.URL+"/ok", "bytes=0-0", pageOrigin)
	get(t, data.URL+"/ok", "bytes=5-9", pageOrigin)
	req, _ := http.NewRequest("OPTIONS", data.URL+"/ok", nil)
	req.Header.Set("Origin", pageOrigin)
	resp, _ := http.DefaultClient.Do(req)
	resp.Body.Close()
	_, b := get(t, data.URL+"/__stats", "", "")
	var st struct {
		Routes map[string]routeStats `json:"routes"`
	}
	json.Unmarshal(b, &st)
	got := st.Routes["ok"]
	if got.Requests != 2 || got.Preflights != 1 || strings.Join(got.Ranges, ",") != "bytes=0-0,bytes=5-9" {
		t.Errorf("%+v", got)
	}
	r, _ := http.Get(data.URL + "/__reset")
	r.Body.Close()
	_, b = get(t, data.URL+"/__stats", "", "")
	if strings.Contains(string(b), `"ok"`) {
		t.Error("reset must clear the counters")
	}
}
