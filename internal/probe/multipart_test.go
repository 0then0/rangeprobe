package probe

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/0then0/rangeprobe/internal/model"
	"github.com/0then0/rangeprobe/internal/rangespec"
	"github.com/0then0/rangeprobe/internal/redact"
	"github.com/0then0/rangeprobe/internal/testsrv"
	"github.com/0then0/rangeprobe/internal/transport"
)

func TestMultipartResponses(t *testing.T) {
	data := testsrv.Content(128)
	copy(data[0:8], []byte("\n--b\r\nx\n")) // a bare LF before a boundary lookalike belongs to these bytes
	requested := [2]rangespec.Spec{rangespec.Int(0, 7), rangespec.Int(16, 23)}
	first := multipartPayload{"Content-Range: bytes 0-7/128\r\n", data[:8]}
	second := multipartPayload{"Content-Range: bytes 16-23/128\r\n", data[16:24]}
	crlf := mimeBody(first, second)
	badSecond := append([]byte(nil), second.body...)
	badSecond[2] ^= 1
	badGap := append([]byte(nil), data[:24]...)
	badGap[10] ^= 1
	noEnding := crlf[:len(crlf)-len("\r\n--b--")]
	lf := append(mimeBodyWithLines("\n", multipartPayload{first.header, []byte("abcdefgh")}, second), '\n')
	var quoted bytes.Buffer
	for _, b := range second.body {
		fmt.Fprintf(&quoted, "=%02X", b)
	}
	const mediaType = `multipart/byteranges; boundary="b"`

	for _, tt := range []struct {
		name, ct, cr, form, coverage, framing, coalescing, issue string
		body                                                     []byte
		status, exit                                             int
		limit                                                    int64
		findings                                                 []string
		parts                                                    []string
	}{
		{name: "crlf with binary lookalike", ct: mediaType, body: crlf, form: "multipart_206", framing: "valid", coverage: "complete", parts: []string{"match", "match"}},
		{name: "reordered is a note", ct: mediaType, body: mimeBody(second, first), form: "multipart_206", framing: "valid", coverage: "complete", findings: []string{"MULTIPART_ORDER"}, parts: []string{"match", "match"}},
		{name: "preamble padding and epilogue", ct: mediaType, body: append([]byte("preamble\r\n\r\n--b \t\r\n"), append(slices.Clone(crlf[len("--b\r\n"):]), []byte("\r\nepilogue")...)...), form: "multipart_206", framing: "valid", coverage: "complete", parts: []string{"match", "match"}},
		{name: "offset union", ct: mediaType, body: mimeBody(multipartPayload{"Content-Range: bytes 0-4/*\r\n", data[:5]}, multipartPayload{"Content-Range: bytes 3-7/128\r\n", data[3:8]}, second), form: "multipart_206", framing: "valid", coverage: "complete", parts: []string{"match", "match", "match"}},
		{name: "coalesced", cr: "bytes 0-23/128", body: data[:24], form: "single_206", coverage: "complete", coalescing: "confirmed", parts: []string{"match"}},
		{name: "coalesced in one MIME part", ct: mediaType, body: mimeBody(multipartPayload{"Content-Range: bytes 0-23/128\r\n", data[:24]}), form: "multipart_206", framing: "valid", coverage: "complete", coalescing: "confirmed", parts: []string{"match"}},
		{name: "coalesced gap mismatch", cr: "bytes 0-23/128", body: badGap, form: "single_206", coverage: "complete", coalescing: "unverified", exit: 1, findings: []string{"MULTIPART_BYTES_MISMATCH"}, parts: []string{"mismatch"}},
		{name: "partial valid coverage", cr: "bytes 16-23/128", body: second.body, form: "single_206", coverage: "partial", exit: 3, findings: []string{"MULTIPART_PARTIAL"}, parts: []string{"match"}},
		{name: "duplicate does not fill coverage", ct: mediaType, body: mimeBody(second, second), form: "multipart_206", framing: "valid", coverage: "partial", exit: 3, findings: []string{"MULTIPART_PARTIAL"}, parts: []string{"match", "match"}},
		{name: "bytes mismatch", ct: mediaType, body: mimeBody(first, multipartPayload{second.header, badSecond}), form: "multipart_206", framing: "valid", coverage: "complete", exit: 1, findings: []string{"MULTIPART_BYTES_MISMATCH"}, parts: []string{"match", "mismatch"}},
		{name: "literal transfer encoding", ct: mediaType, body: mimeBody(first, multipartPayload{second.header + "Content-Transfer-Encoding: quoted-printable\r\n", quoted.Bytes()}), form: "multipart_206", framing: "valid", coverage: "complete", exit: 1, findings: []string{"BODY_EXCESS", "MULTIPART_BYTES_MISMATCH"}, parts: []string{"match", "mismatch"}},
		{name: "missing range in part", ct: mediaType, body: mimeBody(first, multipartPayload{"", second.body}), form: "multipart_206", framing: "valid", coverage: "partial", exit: 1, findings: []string{"MULTIPART_PART_CONTENT_RANGE"}, parts: []string{"match", "not_compared"}},
		{name: "invalid range in part", ct: mediaType, body: mimeBody(first, multipartPayload{"Content-Range: bytes 16-23/23\r\n", second.body}), form: "multipart_206", framing: "valid", coverage: "partial", exit: 1, findings: []string{"MULTIPART_PART_CONTENT_RANGE"}, parts: []string{"match", "not_compared"}},
		{name: "missing single range", body: second.body, form: "single_206", coverage: "unknown", exit: 1, findings: []string{"STATUS_206_NO_CONTENT_RANGE"}, parts: []string{"not_compared"}},
		{name: "malformed single range", cr: "bytes 23-16/128", body: second.body, form: "single_206", coverage: "unknown", exit: 1, findings: []string{"CONTENT_RANGE_INVALID"}, parts: []string{"not_compared"}},
		{name: "single length overflows", cr: "bytes 0-9223372036854775807/*", body: second.body, form: "single_206", coverage: "unknown", exit: 1, findings: []string{"CONTENT_RANGE_OUTSIDE_REQUEST", "NUMBER_OUT_OF_RANGE"}, parts: []string{"not_compared"}},
		{name: "forbidden top Content-Range", ct: mediaType, cr: "bytes 0-23/128", body: crlf, form: "multipart_206", framing: "valid", coverage: "complete", exit: 1, findings: []string{"MULTIPART_TOP_CONTENT_RANGE"}, parts: []string{"match", "match"}},
		{name: "inconsistent totals", ct: mediaType, body: mimeBody(first, multipartPayload{"Content-Range: bytes 16-23/129\r\n", second.body}), form: "multipart_206", framing: "valid", coverage: "complete", exit: 1, findings: []string{"MULTIPART_TOTAL_CONFLICT"}, parts: []string{"match", "match"}},
		{name: "unknown total crosses another part total", ct: mediaType, body: mimeBody(multipartPayload{"Content-Range: bytes 16-23/*\r\n", second.body}, multipartPayload{"Content-Range: bytes 0-7/20\r\n", first.body}), form: "multipart_206", framing: "valid", coverage: "complete", exit: 1, findings: []string{"MULTIPART_TOTAL_CONFLICT"}, parts: []string{"match", "match"}},
		{name: "valid other length", ct: mediaType, body: mimeBody(multipartPayload{"Content-Range: bytes 0-7/120\r\n", first.body}, multipartPayload{"Content-Range: bytes 16-23/120\r\n", second.body}), form: "multipart_206", framing: "valid", coverage: "complete", exit: 3, findings: []string{"REFERENCE_SIZE_MISMATCH"}, parts: []string{"match", "match"}},
		{name: "short delimited part", ct: mediaType, body: mimeBody(first, multipartPayload{second.header, second.body[:4]}), form: "multipart_206", framing: "valid", coverage: "partial", exit: 1, findings: []string{"BODY_TRUNCATED"}, parts: []string{"match", "prefix_match"}},
		{name: "missing boundary parameter", ct: "multipart/byteranges", body: crlf, form: "multipart_206", framing: "invalid", coverage: "unknown", exit: 1, findings: []string{"MULTIPART_CONTENT_TYPE"}},
		{name: "boundary does not match", ct: "multipart/byteranges; boundary=nope", body: crlf, form: "multipart_206", framing: "invalid", coverage: "unknown", exit: 1, findings: []string{"MULTIPART_FRAMING"}},
		{name: "LF delimiters and different bytes", ct: mediaType, body: lf, form: "multipart_206", framing: "invalid", coverage: "complete", exit: 1, findings: []string{"MULTIPART_FRAMING", "MULTIPART_BYTES_MISMATCH"}, parts: []string{"mismatch", "match"}},
		{name: "closing line with bare LF", ct: mediaType, body: append(slices.Clone(crlf), '\n'), form: "multipart_206", framing: "invalid", coverage: "complete", exit: 1, findings: []string{"MULTIPART_FRAMING"}, parts: []string{"match", "match"}},
		{name: "missing closing delimiter", ct: mediaType, body: noEnding, form: "multipart_206", framing: "invalid", coverage: "partial", exit: 1, findings: []string{"MULTIPART_FRAMING"}, parts: []string{"match", "not_compared"}},
		{name: "multipart byte limit cuts off closing delimiter", ct: mediaType, body: crlf, limit: int64(len(crlf) - 2), form: "multipart_206", framing: "incomplete", coverage: "incomplete_observation", issue: "body_limit", exit: 3, findings: []string{"MULTIPART_BODY_LIMIT"}, parts: []string{"match", "not_compared"}},
		{name: "200 full", status: 200, body: data, form: "full_200", coverage: "unknown", exit: 2},
		{name: "200 prefix only", status: 200, body: data, limit: 9, form: "full_200", coverage: "unknown", issue: "body_limit", exit: 3, findings: []string{"MULTIPART_BODY_LIMIT"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			status := tt.status
			if status == 0 {
				status = 206
			}
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Range") != "bytes=0-7,16-23" || r.Header.Get("Accept-Encoding") != "identity" {
					t.Errorf("unexpected request headers: %v", r.Header)
				}
				if tt.ct != "" {
					w.Header().Set("Content-Type", tt.ct)
				}
				if tt.cr != "" {
					w.Header().Set("Content-Range", tt.cr)
				}
				w.Header().Set("Content-Length", strconv.Itoa(len(tt.body)))
				w.WriteHeader(status)
				w.Write(tt.body)
			}))
			defer s.Close()
			limit := tt.limit
			if limit == 0 {
				limit = 2048
			}
			r := runMultipartTest(t, s.URL, data, requested, limit)
			if r.Status != status || r.ExitCode != tt.exit || r.ResponseForm != tt.form || r.Coverage != tt.coverage ||
				r.MultipartFraming != tt.framing || r.Coalescing != tt.coalescing || r.ObservationIssue != tt.issue ||
				r.BytesRead != min(limit, int64(len(tt.body))) || r.BodyComplete != (tt.issue == "") {
				t.Fatalf("unexpected report: %+v", r)
			}
			for _, id := range tt.findings {
				if !multipartHas(r, id) {
					t.Errorf("no %s in %+v", id, r.Findings)
				}
			}
			var got []string
			for _, part := range r.Parts {
				got = append(got, part.Comparison)
			}
			if !slices.Equal(tt.parts, got) {
				t.Errorf("comparison results: got %v, want %v", got, tt.parts)
			}
			if status == 200 {
				want := "match"
				if tt.limit != 0 {
					want = "prefix_match"
				}
				if r.FullComparison == nil || r.FullComparison.Comparison != want {
					t.Errorf("full comparison: %+v, want %s", r.FullComparison, want)
				}
			}
		})
	}
}

func TestMultipartReadAndParseBounds(t *testing.T) {
	data := testsrv.Content(128)
	requested := [2]rangespec.Spec{rangespec.Int(0, 7), rangespec.Int(16, 23)}
	part := multipartPayload{"Content-Range: bytes 0-7/128\r\n", data[:8]}
	for _, tt := range []struct {
		name, issue   string
		body          []byte
		declaredExtra int
		exit          int
		invalidFrame  bool
	}{
		{"cumulative headers", "part_header_limit", mimeBody(
			multipartPayload{part.header + "X-A: " + strings.Repeat("a", 33<<10) + "\r\n", part.body},
			multipartPayload{part.header + "X-B: " + strings.Repeat("b", 33<<10) + "\r\n", part.body},
		), 0, 3, false},
		{"part count", "part_limit", mimeBody(slices.Repeat([]multipartPayload{part}, maxMultipartParts+1)...), 0, 3, false},
		{"header limit after bare LF", "part_header_limit", mimeBody(multipartPayload{
			"Content-Range: bytes 0-7/128\nX-Fill: " + strings.Repeat("z", 70<<10) + "\r\n", part.body,
		}), 0, 1, true},
		{"early HTTP EOF", "truncated", []byte("--b\nContent-Range: bytes 0-7/128\n\n"), 12, 1, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "multipart/byteranges; boundary=b")
				w.Header().Set("Content-Length", strconv.Itoa(len(tt.body)+tt.declaredExtra))
				w.WriteHeader(206)
				w.Write(tt.body)
			}))
			defer s.Close()
			r := runMultipartTest(t, s.URL, data, requested, 128<<10)
			if r.ExitCode != tt.exit || r.ObservationIssue != tt.issue || r.ClosingBoundary || r.BytesRead != int64(len(tt.body)) {
				t.Fatalf("unexpected report: %+v", r)
			}
			if multipartHas(r, "MULTIPART_FRAMING") != tt.invalidFrame {
				t.Fatalf("observed framing violation must survive an incomplete observation: %+v", r)
			}
			if tt.declaredExtra != 0 && (r.BodyComplete || !multipartHas(r, "BODY_TRUNCATED")) {
				t.Fatalf("expected HTTP truncation: %+v", r)
			}
		})
	}
}

func TestMultipartBoundaryPrefixInsidePayload(t *testing.T) {
	data := testsrv.Content(32)
	copy(data, "\r\n--bXyz")
	requested := [2]rangespec.Spec{rangespec.Int(0, 7), rangespec.Int(16, 23)}
	body := mimeBody(multipartPayload{"Content-Range: bytes 0-7/32\r\n", data[:8]},
		multipartPayload{"Content-Range: bytes 16-23/32\r\n", data[16:24]})
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "multipart/byteranges; boundary=b")
		w.WriteHeader(206)
		w.Write(body)
	}))
	defer s.Close()
	r := runMultipartTest(t, s.URL, data, requested, 2048)
	if r.ExitCode != model.ExitProblem || r.MultipartFraming != "invalid" || !r.ClosingBoundary ||
		!multipartHas(r, "MULTIPART_FRAMING") || len(r.Parts) != 2 || r.Parts[0].Comparison != "match" || r.Parts[1].Comparison != "match" {
		t.Fatalf("boundary prefix must be a framing violation while preserving part bytes: %+v", r)
	}
}

func TestMultipartInterruption(t *testing.T) {
	data := testsrv.Content(128)
	requested := [2]rangespec.Spec{rangespec.Int(0, 7), rangespec.Int(16, 23)}
	for _, tt := range []struct {
		name, issue string
		exit        int
	}{
		{"cancelled", "cancelled", model.ExitInterrupted},
		{"request timeout", "timeout", model.ExitIncomplete},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			rd := redact.New(true)
			wait := func() { cancel() }
			deadline := time.Hour
			if tt.issue == "timeout" {
				wait = func() {}
				deadline = 25 * time.Millisecond
			}
			client := transport.New(transport.Config{
				RequestTimeout: deadline, Redactor: rd,
				RoundTripper: multipartRoundTripper(func(r *http.Request) (*http.Response, error) {
					return &http.Response{
						Request: r, StatusCode: 206, ContentLength: -1, Header: http.Header{"Content-Type": {"multipart/byteranges; boundary=b"}},
						Body: &stalledMultipartBody{ctx: r.Context(), onRead: wait},
					}, nil
				}),
			})
			got := Multipart(ctx, client, "http://example.test/file", refFile(t, data), requested, 2048, rd)
			if got.ExitCode != tt.exit || got.ObservationIssue != tt.issue || got.BodyComplete || got.MultipartFraming != "incomplete" || multipartHas(got, "MULTIPART_FRAMING") {
				t.Fatalf("unexpected interrupted report: %+v", got)
			}
		})
	}
}

func TestMultipartCancelledAfterHTTPBody(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	data := testsrv.Content(32)
	requested := [2]rangespec.Spec{rangespec.Int(0, 7), rangespec.Int(16, 23)}
	body := mimeBody(multipartPayload{"Content-Range: bytes 0-7/32\r\n", data[:8]},
		multipartPayload{"Content-Range: bytes 16-23/32\r\n", data[16:24]})
	rd := redact.New(true)
	client := transport.New(transport.Config{
		RequestTimeout: time.Second, Redactor: rd,
		RoundTripper: multipartRoundTripper(func(r *http.Request) (*http.Response, error) {
			return &http.Response{Request: r, StatusCode: 206, ContentLength: int64(len(body)),
				Header: http.Header{"Content-Type": {"multipart/byteranges; boundary=b"}},
				Body:   cancellingMultipartBody{bytes.NewReader(body), cancel},
			}, nil
		}),
	})
	r := Multipart(ctx, client, "http://example.test/file", refFile(t, data), requested, 2048, rd)
	if r.ExitCode != model.ExitInterrupted || r.ObservationIssue != "cancelled" || !r.BodyComplete ||
		r.BytesRead != int64(len(body)) || r.MultipartFraming != "incomplete" || len(r.Parts) != 0 {
		t.Fatalf("HTTP EOF does not establish verification after cancellation: %+v", r)
	}
}

func TestMultipartRangeArithmetic(t *testing.T) {
	const max = math.MaxInt64
	if err := ValidateMultipartRanges([2]rangespec.Spec{rangespec.Int(max-3, max-1), rangespec.Int(0, 1)}, max); err != nil {
		t.Fatal(err)
	}
	if err := ValidateMultipartRanges([2]rangespec.Spec{rangespec.Int(max-3, max), rangespec.Int(0, 1)}, max); err == nil {
		t.Fatal("must reject a last offset at EOF")
	}
}

func TestMultipartCoalescingUnknownOverhead(t *testing.T) {
	data := testsrv.Content(128)
	requested := [2]rangespec.Spec{rangespec.Int(0, 7), rangespec.Int(100, 107)}
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Range", "bytes 0-107/128")
		w.WriteHeader(http.StatusPartialContent)
		w.Write(data[:108])
	}))
	defer s.Close()
	r := runMultipartTest(t, s.URL, data, requested, 108)
	if r.ExitCode != model.ExitIncomplete || r.Coalescing != "overhead_unverified" || r.Coverage != "complete" ||
		!r.BodyComplete || len(r.Parts) != 1 || r.Parts[0].Comparison != "match" || !multipartHas(r, "MULTIPART_COALESCING_UNCERTAIN") {
		t.Fatalf("unexpected coalescing evidence: %+v", r)
	}
}

func TestMultipartHTTPHeaderLimit(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Large", strings.Repeat("x", 70<<10))
		w.WriteHeader(http.StatusPartialContent)
	}))
	defer s.Close()
	requested := [2]rangespec.Spec{rangespec.Int(0, 7), rangespec.Int(16, 23)}
	r := runMultipartTest(t, s.URL, testsrv.Content(128), requested, 256)
	if r.ExitCode != model.ExitIncomplete || r.ObservationIssue != "header_limit" || r.Status != 0 || !multipartHas(r, "MULTIPART_HEADER_LIMIT") {
		t.Fatalf("unexpected header limit evidence: %+v", r)
	}
}

type multipartPayload struct {
	header string
	body   []byte
}

func mimeBody(parts ...multipartPayload) []byte {
	return mimeBodyWithLines("\r\n", parts...)
}

func mimeBodyWithLines(eol string, parts ...multipartPayload) []byte {
	var buf bytes.Buffer
	for i, part := range parts {
		if i != 0 {
			buf.WriteString(eol)
		}
		fmt.Fprintf(&buf, "--b%s%s%s", eol, strings.ReplaceAll(part.header, "\r\n", eol), eol)
		buf.Write(part.body)
	}
	buf.WriteString(eol + "--b--")
	return buf.Bytes()
}

func runMultipartTest(t *testing.T, url string, data []byte, requested [2]rangespec.Spec, limit int64) *model.MultipartReport {
	t.Helper()
	rd := redact.New(true)
	client := transport.New(transport.Config{RequestTimeout: 2 * time.Second, Redactor: rd, MaxResponseHeaderBytes: 64 << 10})
	return Multipart(context.Background(), client, url, refFile(t, data), requested, limit, rd)
}

func multipartHas(r *model.MultipartReport, id string) bool {
	return slices.ContainsFunc(r.Findings, func(f model.Finding) bool { return f.ID == id })
}

type multipartRoundTripper func(*http.Request) (*http.Response, error)

func (f multipartRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type stalledMultipartBody struct {
	ctx    context.Context
	onRead func()
}

func (b *stalledMultipartBody) Read([]byte) (int, error) {
	b.onRead()
	<-b.ctx.Done()
	return 0, b.ctx.Err()
}

func (b *stalledMultipartBody) Close() error { return nil }

type cancellingMultipartBody struct {
	io.Reader
	cancel context.CancelFunc
}

func (b cancellingMultipartBody) Close() error {
	b.cancel()
	return nil
}

func TestGoMultipartAcceptsLF(t *testing.T) {
	const lf = "--b\nContent-Range: bytes 0-2/12\n\nfil\n--b--\n"
	r := multipart.NewReader(strings.NewReader(lf), "b")
	p, err := r.NextRawPart()
	if err != nil {
		t.Fatal(err)
	}
	if b, err := io.ReadAll(p); err != nil || string(b) != "fil" {
		t.Fatalf("raw bytes %q, error %v", b, err)
	}
	if _, err := r.NextRawPart(); err != io.EOF {
		t.Fatalf("Go multipart did not accept the LF closing delimiter: %v", err)
	}
}
