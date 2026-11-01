package probe

import (
	"context"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/0then0/rangeprobe/internal/model"
	"github.com/0then0/rangeprobe/internal/reference"
	"github.com/0then0/rangeprobe/internal/testsrv"
)

const fileSize = 20000

func opts(url string) Options {
	return Options{
		URL: url, ProbeSize: 256,
		Budgets: Budgets{MaxRequests: 16, MaxBytes: 1 << 20, MaxBody: 256 << 10,
			RequestTimeout: 2 * time.Second, RunTimeout: 20 * time.Second, MaxRedirects: 5},
	}
}

func refFile(t *testing.T, data []byte) *reference.File {
	t.Helper()
	p := filepath.Join(t.TempDir(), "ref.bin")
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := reference.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}

// probeServer runs a Run against h. withRef selects reference mode with the
// handler's own data unless ref is given.
func probeServer(t *testing.T, h *testsrv.Handler, withRef bool, mod func(*Options)) *model.Report {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	o := opts(srv.URL + "/data.bin?sig=SECRETSIG")
	if withRef {
		o.Ref = refFile(t, h.Data)
	}
	if mod != nil {
		mod(&o)
	}
	return Run(context.Background(), o)
}

func check(t *testing.T, r *model.Report, id string) model.Check {
	t.Helper()
	for _, c := range r.Checks {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("no check %q", id)
	return model.Check{}
}

func hasFinding(c model.Check, id string) bool {
	for _, f := range c.Findings {
		if f.ID == id {
			return true
		}
	}
	return false
}

func finding(t *testing.T, c model.Check, id string) model.Finding {
	t.Helper()
	for _, f := range c.Findings {
		if f.ID == id {
			return f
		}
	}
	t.Fatalf("check %s has no finding %s: %+v", c.ID, id, c.Findings)
	return model.Finding{}
}

func wantStatus(t *testing.T, r *model.Report, id string, want model.Status) {
	t.Helper()
	if got := check(t, r, id).Status; got != want {
		c := check(t, r, id)
		t.Errorf("%s: status %s, want %s; findings: %+v skip: %+v", id, got, want, c.Findings, c.Skip)
	}
}

func allChecks(t *testing.T, r *model.Report, want model.Status) {
	t.Helper()
	for _, c := range r.Checks {
		wantStatus(t, r, c.ID, want)
	}
}

func TestCorrectServerReferenceMode(t *testing.T) {
	h := &testsrv.Handler{Data: testsrv.Content(fileSize), ETag: `"v1"`, LastModified: "Wed, 21 Oct 2015 07:28:00 GMT"}
	r := probeServer(t, h, true, nil)
	allChecks(t, r, model.KindPass)
	if r.Summary.ExitCode != model.ExitPass || r.Summary.Result != model.ResultPass {
		t.Fatalf("summary %+v", r.Summary)
	}
	if len(r.Checks) != 10 || r.Budget.Requests != 10 {
		t.Errorf("checks %d requests %d", len(r.Checks), r.Budget.Requests)
	}
	mid := check(t, r, "middle")
	if mid.Body.Reference == nil || !mid.Body.Reference.Match || mid.Body.Reference.Compared != 256 {
		t.Errorf("middle was not compared byte for byte: %+v", mid.Body)
	}
	if got := mid.Request.Range; got != "bytes=9872-10127" {
		t.Errorf("middle range %s", got)
	}
	if r.Representation.Length == nil || *r.Representation.Length != fileSize || r.Representation.LengthBasis != "content-range" {
		t.Errorf("representation %+v", r.Representation)
	}
	// Unsatisfiable was sent only because the *server* reported the length.
	if u := check(t, r, "unsatisfiable"); u.Response.Status != 416 {
		t.Errorf("unsatisfiable got %d", u.Response.Status)
	}
	if len(r.VerifiedClaims) == 0 {
		t.Error("no verified claims listed")
	}
}

func TestCorrectServerObserveMode(t *testing.T) {
	h := &testsrv.Handler{Data: testsrv.Content(fileSize), ETag: `"v1"`}
	r := probeServer(t, h, false, nil)
	allChecks(t, r, model.KindPass)
	if r.Run.Mode != "observe" || r.Reference != nil || r.Summary.ExitCode != 0 {
		t.Errorf("unexpected: %+v", r.Run.Mode)
	}
	for _, c := range r.Checks {
		if c.Body != nil && c.Body.Reference != nil {
			t.Errorf("%s: observe mode must not report reference comparison", c.ID)
		}
		if c.Status == model.KindPass && !strings.Contains(strings.Join(c.Limits, " "), "identity with the original") {
			t.Errorf("%s: observe limits missing: %v", c.ID, c.Limits)
		}
	}
	if !strings.Contains(r.Summary.Headline, "not proven") {
		t.Errorf("headline overpromises: %s", r.Summary.Headline)
	}
	ov := check(t, r, "overlap")
	if !strings.Contains(strings.Join(ov.Verified, " "), "consistency, not correctness") {
		t.Errorf("overlap claim: %v", ov.Verified)
	}
}

func TestNoValidatorsAddsLimitNotFailure(t *testing.T) {
	h := &testsrv.Handler{Data: testsrv.Content(fileSize)}
	r := probeServer(t, h, false, nil)
	allChecks(t, r, model.KindPass)
	found := false
	for _, f := range r.RunFindings {
		found = found || f.ID == "WEAK_VALIDATORS"
	}
	if !found {
		t.Error("missing WEAK_VALIDATORS note")
	}
	if !hasFinding(check(t, r, "reread"), "WEAK_VALIDATORS") {
		t.Error("agreement without a strong ETag should say identity is not established")
	}
}

func TestRangeIgnoredIsNotAViolation(t *testing.T) {
	h := &testsrv.Handler{Data: testsrv.Content(fileSize), ETag: `"v1"`}
	h.Tamper = func(r *testsrv.Reply) {
		if r.Range != "" {
			r.Status, r.Body = 200, h.Data
			r.Header.Del("Content-Range")
		}
	}
	r := probeServer(t, h, true, nil)
	if r.Summary.ExitCode != model.ExitRangeIgnored || r.Summary.Result != model.ResultRangeIgnored {
		t.Fatalf("summary %+v", r.Summary)
	}
	for _, c := range r.Checks {
		if c.Status != model.KindRangeIgnored {
			t.Errorf("%s: %s %+v", c.ID, c.Status, c.Findings)
		}
		for _, f := range c.Findings {
			if f.Kind == model.KindViolation {
				t.Errorf("%s: 200 must not be a violation: %s", c.ID, f.ID)
			}
		}
	}
	// The full body is small, so it was read to the end and compared.
	if b := check(t, r, "head").Body; b.EndState != "complete" || b.Reference == nil || !b.Reference.Match {
		t.Errorf("full 200 body not verified: %+v", b)
	}
	// The unsatisfiable probe only ran because the 200 reported a length.
	if r.Representation.LengthBasis != "content-length-200" {
		t.Errorf("basis %q", r.Representation.LengthBasis)
	}
}

func TestHugeFullResponseStopsAtBudget(t *testing.T) {
	chunk := make([]byte, 1<<16)
	var served atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", strconv.FormatInt(1<<40, 10)) // 1 TiB
		w.WriteHeader(200)
		for i := 0; i < 1<<20; i++ {
			n, err := w.Write(chunk)
			served.Add(int64(n))
			if err != nil {
				return
			}
		}
	}))
	defer srv.Close()
	o := opts(srv.URL)
	o.Budgets.MaxBytes = 300 << 10
	start := time.Now()
	r := Run(context.Background(), o)
	if r.Budget.BytesRead > o.Budgets.MaxBytes {
		t.Fatalf("read %d bytes, budget %d", r.Budget.BytesRead, o.Budgets.MaxBytes)
	}
	if time.Since(start) > 10*time.Second {
		t.Error("took too long")
	}
	fb := check(t, r, "first-byte")
	if fb.Status != model.KindRangeIgnored || fb.Body.EndState != "prefix" || fb.Body.Complete {
		t.Errorf("first-byte: %s %+v", fb.Status, fb.Body)
	}
	if fb.Body.BytesRead > ignoredPrefix {
		t.Errorf("read %d from an ignored-range response", fb.Body.BytesRead)
	}
	if r.Summary.ExitCode != model.ExitRangeIgnored {
		t.Errorf("exit %d", r.Summary.ExitCode)
	}
	skipped := 0
	for _, c := range r.Checks {
		if c.Skip != nil && c.Skip.ID == "SKIP_BUDGET_BYTES" {
			skipped++
		}
	}
	if skipped == 0 {
		t.Error("the byte budget should have caused skips")
	}
}

func TestWrongContentRange(t *testing.T) {
	h := &testsrv.Handler{Data: testsrv.Content(fileSize), ETag: `"v1"`}
	h.Tamper = func(r *testsrv.Reply) {
		if r.Range == "bytes=0-255" {
			r.Header.Set("Content-Range", fmt.Sprintf("bytes 1-256/%d", fileSize)) // shifted claim, same length
		}
	}
	r := probeServer(t, h, true, nil)
	c := check(t, r, "head")
	if c.Status != model.KindViolation {
		t.Fatalf("status %s: %+v", c.Status, c.Findings)
	}
	// The bytes are those of 0-255, so against the claimed 1-256 they differ too.
	if !hasFinding(c, "BYTES_MISMATCH_REFERENCE") {
		t.Error("the claimed interval's bytes were compared with the reference")
	}
	f := finding(t, c, "CONTENT_RANGE_OUTSIDE_REQUEST")
	if f.Conditions == nil || len(f.Evidence) == 0 {
		t.Errorf("finding lacks conditions or evidence: %+v", f)
	}
	if r.Summary.ExitCode != model.ExitProblem {
		t.Errorf("exit %d", r.Summary.ExitCode)
	}
}

func TestMalformedContentRangeVariants(t *testing.T) {
	cases := map[string]struct {
		cr   string
		drop bool
		id   string
		kind model.Kind
	}{
		"missing":      {drop: true, id: "STATUS_206_NO_CONTENT_RANGE", kind: model.KindViolation},
		"garbage":      {cr: "bytes zero-nine/10", id: "CONTENT_RANGE_INVALID", kind: model.KindViolation},
		"last<first":   {cr: "bytes 9-0/20000", id: "CONTENT_RANGE_INVALID", kind: model.KindViolation},
		"total<=last":  {cr: "bytes 0-255/200", id: "CONTENT_RANGE_INVALID", kind: model.KindViolation},
		"unit":         {cr: "items 0-255/20000", id: "CONTENT_RANGE_INVALID", kind: model.KindViolation},
		"unsatisfied":  {cr: "bytes */20000", id: "CONTENT_RANGE_INVALID", kind: model.KindViolation},
		"huge number":  {cr: "bytes 0-255/99999999999999999999", id: "NUMBER_OUT_OF_RANGE", kind: model.KindInconclusive},
		"huge as 2^63": {cr: "bytes 0-255/9223372036854775808", id: "NUMBER_OUT_OF_RANGE", kind: model.KindInconclusive},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			h := &testsrv.Handler{Data: testsrv.Content(fileSize), ETag: `"v1"`}
			h.Tamper = func(r *testsrv.Reply) {
				if r.Range == "bytes=0-255" {
					if tc.drop {
						r.Header.Del("Content-Range")
					} else {
						r.Header.Set("Content-Range", tc.cr)
					}
				}
			}
			r := probeServer(t, h, true, nil)
			c := check(t, r, "head")
			if f := finding(t, c, tc.id); f.Kind != tc.kind || c.Status != tc.kind {
				t.Errorf("kind %s, check %s", f.Kind, c.Status)
			}
		})
	}
}

func TestRightHeadersWrongBytes(t *testing.T) {
	h := &testsrv.Handler{Data: testsrv.Content(fileSize), ETag: `"v1"`}
	h.Tamper = func(r *testsrv.Reply) {
		if r.Range == "bytes=-256" {
			b := append([]byte(nil), r.Body...)
			b[100] ^= 0xFF
			r.Body = b
		}
	}
	r := probeServer(t, h, true, nil)
	c := check(t, r, "suffix")
	if c.Status != model.KindByteMismatch {
		t.Fatalf("status %s: %+v", c.Status, c.Findings)
	}
	cmp := c.Body.Reference
	if cmp.FirstMismatch == nil || *cmp.FirstMismatch != fileSize-256+100 || cmp.MismatchCount != 1 || cmp.Match {
		t.Errorf("comparison %+v", cmp)
	}
	f := finding(t, c, "BYTES_MISMATCH_REFERENCE")
	if !strings.Contains(strings.Join(f.Limits, " "), "different file or version") {
		t.Errorf("a mismatch must not be presented as proof of a Range defect: %v", f.Limits)
	}
	if cmp.Fragment != nil {
		t.Error("fragments are opt-in")
	}
	if r.Summary.ExitCode != model.ExitProblem {
		t.Errorf("exit %d", r.Summary.ExitCode)
	}
	if strings.Contains(r.Summary.MismatchPattern, "every compared") {
		t.Errorf("only one response differs: %s", r.Summary.MismatchPattern)
	}
}

func TestDumpMismatchIsExplicitOptIn(t *testing.T) {
	h := &testsrv.Handler{Data: testsrv.Content(fileSize), ETag: `"v1"`}
	h.Tamper = func(r *testsrv.Reply) {
		if r.Range == "bytes=0-255" {
			b := append([]byte(nil), r.Body...)
			b[7] ^= 1
			r.Body = b
		}
	}
	r := probeServer(t, h, true, func(o *Options) { o.DumpMismatch = 8 })
	fr := check(t, r, "head").Body.Reference.Fragment
	if fr == nil || fr.Offset != 7 || len(fr.Observed) != 16 {
		t.Errorf("fragment %+v", fr)
	}
}

func TestOneByteOffsetIsReported(t *testing.T) {
	h := &testsrv.Handler{Data: testsrv.Content(fileSize), ETag: `"v1"`}
	h.Tamper = func(r *testsrv.Reply) {
		if r.Range == "bytes=9872-10127" { // middle: serve the bytes one position later
			r.Body = h.Data[r.Start+1 : r.End+2]
		}
	}
	r := probeServer(t, h, true, nil)
	c := check(t, r, "middle")
	if c.Status != model.KindByteMismatch {
		t.Fatalf("status %s", c.Status)
	}
	if hint := c.Body.Reference.ShiftHint; !strings.Contains(hint, "offset+1") {
		t.Errorf("shift hint %q", hint)
	}
}

func TestEmptyAndTruncatedBodies(t *testing.T) {
	for name, cut := range map[string]int{"empty": 0, "truncated": 100} {
		t.Run(name, func(t *testing.T) {
			h := &testsrv.Handler{Data: testsrv.Content(fileSize), ETag: `"v1"`}
			h.Tamper = func(r *testsrv.Reply) {
				if r.Range == "bytes=19744-19999" {
					r.CutAfter = cut
				}
			}
			r := probeServer(t, h, true, nil)
			c := check(t, r, "tail")
			if c.Status != model.KindViolation {
				t.Fatalf("a body shorter than Content-Length is not a transport error here: %s %+v", c.Status, c.Findings)
			}
			f := finding(t, c, "BODY_TRUNCATED")
			if !strings.Contains(strings.Join(f.Limits, " "), "repeat") {
				t.Errorf("limits should mention infrastructure: %v", f.Limits)
			}
			if c.Body.Complete || c.Body.BytesRead != int64(cut) {
				t.Errorf("body %+v", c.Body)
			}
			if len(c.Verified) != 0 {
				t.Errorf("a truncated body must not count as verified: %v", c.Verified)
			}
		})
	}
}

func TestExtraBytesAndMissingContentLength(t *testing.T) {
	h := &testsrv.Handler{Data: testsrv.Content(fileSize), ETag: `"v1"`}
	h.Tamper = func(r *testsrv.Reply) {
		if r.Range == "bytes=0-255" {
			r.NoContentLength = true
			r.Body = append(append([]byte(nil), r.Body...), 0xAB, 0xCD)
		}
	}
	r := probeServer(t, h, true, nil)
	c := check(t, r, "head")
	if c.Status != model.KindViolation || !hasFinding(c, "BODY_EXCESS") {
		t.Fatalf("%s %+v", c.Status, c.Findings)
	}
	if c.Body.BytesRead != 257 {
		t.Errorf("only one octet beyond the declared length should be read, got %d bytes", c.Body.BytesRead)
	}
	if c.Body.Reference != nil && c.Body.Reference.MismatchCount != 0 {
		t.Error("the probe octet must not be compared with the reference")
	}
}

func TestChunkedExactBodyPasses(t *testing.T) {
	h := &testsrv.Handler{Data: testsrv.Content(fileSize), ETag: `"v1"`}
	h.Tamper = func(r *testsrv.Reply) { r.NoContentLength = r.Range != "" }
	r := probeServer(t, h, true, nil)
	allChecks(t, r, model.KindPass)
	if !check(t, r, "head").Response.Chunked || check(t, r, "head").Response.ContentLength != nil {
		t.Errorf("expected a response without Content-Length: %+v", check(t, r, "head").Response)
	}
}

func TestContentLengthDisagreesWithContentRange(t *testing.T) {
	h := &testsrv.Handler{Data: testsrv.Content(fileSize), ETag: `"v1"`}
	h.Tamper = func(r *testsrv.Reply) {
		if r.Range == "bytes=0-255" {
			r.Header.Set("Content-Range", fmt.Sprintf("bytes 0-299/%d", fileSize))
		}
	}
	r := probeServer(t, h, true, nil)
	c := check(t, r, "head")
	if !hasFinding(c, "CONTENT_LENGTH_RANGE_MISMATCH") || !hasFinding(c, "CONTENT_RANGE_OUTSIDE_REQUEST") {
		t.Errorf("findings %+v", c.Findings)
	}
}

func TestPartialSubsetIsAllowed(t *testing.T) {
	h := &testsrv.Handler{Data: testsrv.Content(fileSize), ETag: `"v1"`}
	h.Tamper = func(r *testsrv.Reply) {
		if r.Range == "bytes=0-255" { // RFC 9110 15.3.7: a server may send less than asked
			r.Body = h.Data[0:100]
			r.Header.Set("Content-Range", fmt.Sprintf("bytes 0-99/%d", fileSize))
		}
	}
	r := probeServer(t, h, true, nil)
	c := check(t, r, "head")
	if c.Status != model.KindPass || !hasFinding(c, "PARTIAL_RESPONSE") {
		t.Errorf("%s %+v", c.Status, c.Findings)
	}
}

func TestEOFClampingAndUnsatisfiable(t *testing.T) {
	h := &testsrv.Handler{Data: testsrv.Content(fileSize), ETag: `"v1"`}
	r := probeServer(t, h, true, nil)
	p := check(t, r, "past-eof")
	if p.Response.Status != 206 || p.Body.BytesRead != 128 {
		t.Errorf("past-eof: %+v %+v", p.Response, p.Body)
	}
	var cr string
	for _, kv := range p.Response.Headers {
		if kv.Key == "Content-Range" {
			cr = kv.Value
		}
	}
	if cr != "bytes 19872-19999/20000" {
		t.Errorf("clamped Content-Range %q", cr)
	}

	h2 := &testsrv.Handler{Data: testsrv.Content(fileSize), ETag: `"v1"`}
	h2.Tamper = func(r *testsrv.Reply) {
		if r.Range == "bytes=20000-" {
			r.Status = 206
			r.Header.Set("Content-Range", "bytes 20000-20255/20256")
			r.Body = make([]byte, 256)
		}
	}
	r = probeServer(t, h2, true, nil)
	// The 206 names a new, larger length: that is a changed representation
	// signal, not a conclusion about satisfiability.
	if c := check(t, r, "unsatisfiable"); c.Status != model.KindInconclusive || !hasFinding(c, "REPRESENTATION_CHANGED") {
		t.Errorf("%s %+v", c.Status, c.Findings)
	}

	h3 := &testsrv.Handler{Data: testsrv.Content(fileSize), ETag: `"v1"`}
	h3.Tamper = func(r *testsrv.Reply) {
		if r.Range == "bytes=20000-" {
			r.Status = 206
			r.Header.Set("Content-Range", fmt.Sprintf("bytes 20000-20000/%d", fileSize))
			r.Body = []byte{0}
		}
	}
	r = probeServer(t, h3, true, nil)
	if c := check(t, r, "unsatisfiable"); c.Status != model.KindViolation {
		t.Errorf("%s %+v", c.Status, c.Findings)
	}
}

func TestSatisfiable416IsAViolationOnlyWithSelfContradiction(t *testing.T) {
	h := &testsrv.Handler{Data: testsrv.Content(fileSize), ETag: `"v1"`}
	h.Tamper = func(r *testsrv.Reply) {
		if r.Range == "bytes=9872-10127" {
			r.Status, r.Body = 416, nil
			r.Header.Set("Content-Range", fmt.Sprintf("bytes */%d", fileSize))
		}
	}
	r := probeServer(t, h, true, nil)
	if c := check(t, r, "middle"); c.Status != model.KindViolation || !hasFinding(c, "SATISFIABLE_GOT_416") {
		t.Errorf("%s %+v", c.Status, c.Findings)
	}

	h2 := &testsrv.Handler{Data: testsrv.Content(fileSize), ETag: `"v1"`}
	h2.Tamper = func(r *testsrv.Reply) {
		if r.Range == "bytes=9872-10127" {
			r.Status, r.Body = 416, nil
			r.Header.Set("Content-Range", "bytes */5000") // file shrank
		}
	}
	r = probeServer(t, h2, true, nil)
	if c := check(t, r, "middle"); c.Status == model.KindViolation {
		t.Errorf("416 for a shrunk file must not be a violation: %+v", c.Findings)
	}
}

func TestRepresentationChangeIsInconclusiveNotAViolation(t *testing.T) {
	h := &testsrv.Handler{Data: testsrv.Content(fileSize), ETag: `"v1"`}
	var n atomic.Int32
	h.Tamper = func(r *testsrv.Reply) {
		if n.Add(1) >= 3 && r.Start >= 0 { // from the 3rd request (middle) the file has been replaced
			r.Header.Set("ETag", `"v2"`)
			b := append([]byte(nil), r.Body...)
			for i := range b {
				b[i] ^= 0x5A
			}
			r.Body = b
		}
	}
	r := probeServer(t, h, true, nil)
	if r.Summary.Result == model.ResultProblem {
		t.Fatalf("a changed file must not be reported as a defect: %+v", r.Summary)
	}
	if r.Summary.ExitCode != model.ExitIncomplete {
		t.Errorf("exit %d", r.Summary.ExitCode)
	}
	mid := check(t, r, "middle")
	if mid.Status != model.KindInconclusive || !hasFinding(mid, "REPRESENTATION_CHANGED") {
		t.Fatalf("middle: %s %+v", mid.Status, mid.Findings)
	}
	f := finding(t, mid, "BYTES_MISMATCH_REFERENCE")
	if f.Kind != model.KindInconclusive {
		t.Errorf("the byte mismatch must be downgraded, got %s", f.Kind)
	}
	if r.Representation.Stable || len(r.Representation.Changes) == 0 {
		t.Errorf("representation %+v", r.Representation)
	}
	if check(t, r, "head").Status != model.KindPass {
		t.Error("responses before the change keep their verdict")
	}
}

func TestStrongETagMakesRereadMismatchAViolation(t *testing.T) {
	var calls atomic.Int32
	mk := func(etag string) *testsrv.Handler {
		calls.Store(0)
		h := &testsrv.Handler{Data: testsrv.Content(fileSize), ETag: etag}
		h.Tamper = func(r *testsrv.Reply) {
			if r.Range == "bytes=9872-10127" && calls.Add(1) == 2 { // the re-read
				b := append([]byte(nil), r.Body...)
				b[5] ^= 0xFF
				r.Body = b
			}
		}
		return h
	}
	r := probeServer(t, mk(`"v1"`), false, nil)
	if c := check(t, r, "reread"); c.Status != model.KindViolation || !hasFinding(c, "REREAD_INCONSISTENT") {
		t.Errorf("strong: %s %+v", c.Status, c.Findings)
	}
	for _, etag := range []string{"", `W/"v1"`} {
		r = probeServer(t, mk(etag), false, nil)
		c := check(t, r, "reread")
		if c.Status != model.KindInconclusive || !hasFinding(c, "CONSISTENCY_UNATTRIBUTED") {
			t.Errorf("etag %q: %s %+v", etag, c.Status, c.Findings)
		}
		if r.Summary.Result == model.ResultProblem {
			t.Errorf("etag %q: no problem may be confirmed without a strong validator", etag)
		}
	}
}

func TestOverlapInconsistencyUnderStrongETag(t *testing.T) {
	h := &testsrv.Handler{Data: testsrv.Content(fileSize), ETag: `"v1"`}
	h.Tamper = func(r *testsrv.Reply) {
		if r.Range == "bytes=10000-10255" { // overlap-b: wrong bytes only in the shared window
			b := append([]byte(nil), r.Body...)
			b[0] ^= 0xFF
			r.Body = b
		}
	}
	r := probeServer(t, h, false, nil)
	if c := check(t, r, "overlap"); c.Status != model.KindViolation || !hasFinding(c, "OVERLAP_INCONSISTENT") {
		t.Errorf("%s %+v", c.Status, c.Findings)
	}
}

func TestContentEncodingIsNotCompared(t *testing.T) {
	h := &testsrv.Handler{Data: testsrv.Content(fileSize), ETag: `"v1"`}
	h.Tamper = func(r *testsrv.Reply) {
		if r.Range == "bytes=0-255" {
			r.Header.Set("Content-Encoding", "gzip")
			b := append([]byte(nil), r.Body...)
			b[3] ^= 0xFF // differs from the reference, as encoded bytes would
			r.Body = b
		}
	}
	r := probeServer(t, h, true, nil)
	c := check(t, r, "head")
	if c.Status != model.KindInconclusive || !hasFinding(c, "ENCODING_UNSUPPORTED") || hasFinding(c, "BYTES_MISMATCH_REFERENCE") {
		t.Errorf("%s %+v", c.Status, c.Findings)
	}
	if c.Body.Reference != nil {
		t.Error("encoded bytes must not be compared with the reference")
	}
	if r.Summary.Result != model.ResultIncomplete {
		t.Errorf("result %s", r.Summary.Result)
	}
}

func TestMultipartIsHandledConservatively(t *testing.T) {
	h := &testsrv.Handler{Data: testsrv.Content(fileSize), ETag: `"v1"`}
	h.Tamper = func(r *testsrv.Reply) {
		if r.Range == "bytes=0-255" {
			r.Header.Set("Content-Type", "multipart/byteranges; boundary=XYZ")
			r.Header.Del("Content-Range")
			r.Body = []byte("--XYZ\r\nContent-Range: bytes 0-255/20000\r\n\r\n" + strings.Repeat("a", 256) + "\r\n--XYZ--")
		}
	}
	r := probeServer(t, h, true, nil)
	c := check(t, r, "head")
	if c.Status != model.KindInconclusive || !hasFinding(c, "MULTIPART_UNSUPPORTED") || c.Body.BytesRead != 0 {
		t.Errorf("%s %+v body %+v", c.Status, c.Findings, c.Body)
	}
}

func TestReferenceSizeMismatchBlocksConclusions(t *testing.T) {
	h := &testsrv.Handler{Data: testsrv.Content(fileSize), ETag: `"v1"`}
	r := probeServer(t, h, false, func(o *Options) {
		o.Ref = refFile(t, testsrv.Content(fileSize-1000)) // an older, shorter file
	})
	if r.Summary.Result == model.ResultProblem {
		t.Fatalf("different reference must not produce a problem verdict: %+v", r.Summary)
	}
	if !hasFinding(check(t, r, "first-byte"), "REFERENCE_SIZE_MISMATCH") {
		t.Error("missing REFERENCE_SIZE_MISMATCH")
	}
	for _, c := range r.Checks {
		for _, f := range c.Findings {
			if f.Kind == model.KindByteMismatch {
				t.Errorf("%s: byte_mismatch despite a size mismatch", c.ID)
			}
		}
	}
	// The plan uses the length the server reported, not the reference's.
	if r.Representation.Length == nil || *r.Representation.Length != fileSize {
		t.Errorf("length %+v", r.Representation.Length)
	}
}

func TestReferenceShorterIsNotRemoteSize(t *testing.T) {
	// Server ignores Range and gives no length: only the reference size is
	// known, and it must not enable the unsatisfiable check.
	data := testsrv.Content(fileSize)
	h := &testsrv.Handler{Data: data, ETag: `"v1"`}
	h.Tamper = func(r *testsrv.Reply) {
		r.Status = 200
		r.Header.Del("Content-Range")
		r.Body = data
		r.NoContentLength = true
	}
	r := probeServer(t, h, true, nil)
	u := check(t, r, "unsatisfiable")
	if u.Skip == nil || u.Skip.ID != "SKIP_REMOTE_SIZE" {
		t.Errorf("unsatisfiable: %+v", u.Skip)
	}
	if r.Representation.Length != nil {
		t.Errorf("reference length must not be reported as the remote length: %d", *r.Representation.Length)
	}
}

func TestZeroLengthFile(t *testing.T) {
	h := &testsrv.Handler{Data: []byte{}, ETag: `"v1"`}
	r := probeServer(t, h, true, nil)
	if r.Budget.Requests != 1 {
		t.Errorf("requests %d", r.Budget.Requests)
	}
	if r.Summary.ExitCode != model.ExitIncomplete {
		t.Errorf("an empty file cannot be fully verified: exit %d", r.Summary.ExitCode)
	}
}

func TestRequestBudget(t *testing.T) {
	h := &testsrv.Handler{Data: testsrv.Content(fileSize), ETag: `"v1"`}
	r := probeServer(t, h, true, func(o *Options) { o.Budgets.MaxRequests = 3 })
	if r.Budget.Requests != 3 || len(h.Requests()) != 3 {
		t.Fatalf("requests %d / %d", r.Budget.Requests, len(h.Requests()))
	}
	if c := check(t, r, "suffix"); c.Skip == nil || c.Skip.ID != "SKIP_BUDGET_REQUESTS" {
		t.Errorf("%+v", c.Skip)
	}
	if r.Summary.ExitCode != model.ExitIncomplete {
		t.Errorf("missing key checks must not look like PASS, exit %d", r.Summary.ExitCode)
	}
}

func TestByteBudgetIsNeverExceeded(t *testing.T) {
	h := &testsrv.Handler{Data: testsrv.Content(fileSize), ETag: `"v1"`}
	r := probeServer(t, h, true, func(o *Options) { o.Budgets.MaxBytes = 600 })
	if r.Budget.BytesRead > 600 {
		t.Fatalf("read %d > 600", r.Budget.BytesRead)
	}
	var skipped bool
	for _, c := range r.Checks {
		skipped = skipped || (c.Skip != nil && c.Skip.ID == "SKIP_BUDGET_BYTES")
	}
	if !skipped || r.Summary.ExitCode != model.ExitIncomplete {
		t.Errorf("skipped=%v exit=%d", skipped, r.Summary.ExitCode)
	}
}

func TestRequestTimeoutIsTransportError(t *testing.T) {
	h := &testsrv.Handler{Data: testsrv.Content(fileSize), ETag: `"v1"`}
	h.Tamper = func(r *testsrv.Reply) {
		if r.Range == "bytes=-256" {
			r.Delay = 700 * time.Millisecond
		}
	}
	r := probeServer(t, h, true, func(o *Options) { o.Budgets.RequestTimeout = 150 * time.Millisecond })
	c := check(t, r, "suffix")
	if c.Status != model.KindTransportError || !hasFinding(c, "REQUEST_TIMEOUT") {
		t.Errorf("%s %+v", c.Status, c.Findings)
	}
	if len(c.Verified) != 0 {
		t.Error("a timeout verifies nothing")
	}
	if check(t, r, "tail").Status != model.KindPass {
		t.Error("later checks must still run")
	}
}

func TestRunTimeoutSkipsRest(t *testing.T) {
	h := &testsrv.Handler{Data: testsrv.Content(fileSize), ETag: `"v1"`}
	h.Tamper = func(r *testsrv.Reply) { r.Delay = 150 * time.Millisecond }
	start := time.Now()
	r := probeServer(t, h, true, func(o *Options) { o.Budgets.RunTimeout = 400 * time.Millisecond })
	if time.Since(start) > 3*time.Second {
		t.Error("run timeout not enforced")
	}
	n := 0
	for _, c := range r.Checks {
		if c.Skip != nil && c.Skip.ID == "SKIP_BUDGET_TIME" {
			n++
		}
	}
	if n == 0 || r.Summary.ExitCode != model.ExitIncomplete {
		t.Errorf("skipped %d exit %d", n, r.Summary.ExitCode)
	}
}

func TestCancellation(t *testing.T) {
	h := &testsrv.Handler{Data: testsrv.Content(fileSize), ETag: `"v1"`}
	h.Tamper = func(r *testsrv.Reply) { r.Delay = 100 * time.Millisecond }
	srv := httptest.NewServer(h)
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(250*time.Millisecond, cancel)
	r := Run(ctx, opts(srv.URL))
	if !r.Run.Interrupted {
		t.Error("not marked interrupted")
	}
	var cancelled int
	for _, c := range r.Checks {
		if c.Skip != nil && c.Skip.ID == "SKIP_CANCELLED" {
			cancelled++
		}
	}
	if cancelled == 0 {
		t.Error("remaining checks should be skipped as cancelled")
	}
}

func TestPreconditionsUseStrongETag(t *testing.T) {
	h := &testsrv.Handler{Data: testsrv.Content(fileSize), ETag: `"v1"`}
	r := probeServer(t, h, true, func(o *Options) { o.Preconditions = true })
	allChecks(t, r, model.KindPass)
	logs := h.Requests()
	if logs[0].Header.Get("If-Match") != "" {
		t.Error("first request has no ETag to send")
	}
	for _, l := range logs[1:] {
		if l.Header.Get("If-Match") != `"v1"` {
			t.Fatalf("If-Match = %q", l.Header.Get("If-Match"))
		}
	}

	h2 := &testsrv.Handler{Data: testsrv.Content(fileSize), ETag: `"v1"`}
	h2.Tamper = func(r *testsrv.Reply) {
		if r.Range == "bytes=-256" {
			r.Status, r.Body = 412, nil
			r.Header.Del("Content-Range")
		}
	}
	r = probeServer(t, h2, true, func(o *Options) { o.Preconditions = true })
	if c := check(t, r, "suffix"); c.Status != model.KindInconclusive || !hasFinding(c, "PRECONDITION_FAILED") {
		t.Errorf("%s %+v", c.Status, c.Findings)
	}

	h3 := &testsrv.Handler{Data: testsrv.Content(fileSize), ETag: `W/"v1"`}
	probeServer(t, h3, true, func(o *Options) { o.Preconditions = true })
	for _, l := range h3.Requests() {
		if l.Header.Get("If-Match") != "" {
			t.Error("a weak ETag must never be used in If-Match")
		}
	}
}

func TestStatusClassification(t *testing.T) {
	cases := map[int]struct {
		id   string
		kind model.Kind
	}{
		404: {"HTTP_STATUS_UNEXPECTED", model.KindInconclusive},
		403: {"HTTP_STATUS_UNEXPECTED", model.KindInconclusive},
		503: {"HTTP_SERVER_ERROR", model.KindTransportError},
		429: {"HTTP_SERVER_ERROR", model.KindTransportError},
	}
	for status, want := range cases {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status) }))
		r := Run(context.Background(), opts(srv.URL))
		srv.Close()
		c := check(t, r, "first-byte")
		if c.Status != want.kind || !hasFinding(c, want.id) {
			t.Errorf("%d: %s %+v", status, c.Status, c.Findings)
		}
		if r.Summary.ExitCode != model.ExitIncomplete {
			t.Errorf("%d: exit %d", status, r.Summary.ExitCode)
		}
	}
}

// synthetic serves a file of declared size with deterministic content
// without ever allocating it, to exercise offsets near the int64 limit.
func synthetic(total string, size int64) http.Handler {
	at := func(i int64) byte { return byte(i*131 + i>>9 + i>>21) }
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		spec := strings.TrimPrefix(r.Header.Get("Range"), "bytes=")
		a, b, _ := strings.Cut(spec, "-")
		w.Header().Set("ETag", `"big"`)
		var first, last int64
		switch {
		case a == "":
			n, _ := strconv.ParseInt(b, 10, 64)
			first, last = max(0, size-n), size-1
		default:
			first, _ = strconv.ParseInt(a, 10, 64)
			last = size - 1
			if b != "" {
				v, _ := strconv.ParseInt(b, 10, 64)
				last = min(v, size-1)
			}
		}
		if first >= size {
			w.Header().Set("Content-Range", "bytes */"+total)
			w.WriteHeader(416)
			return
		}
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%s", first, last, total))
		w.Header().Set("Content-Length", strconv.FormatInt(last-first+1, 10))
		w.WriteHeader(206)
		for i := first; ; i++ {
			w.Write([]byte{at(i)})
			if i == last {
				break
			}
		}
	})
}

func TestOffsetsNearInt64Limit(t *testing.T) {
	srv := httptest.NewServer(synthetic("9223372036854775807", math.MaxInt64))
	defer srv.Close()
	r := Run(context.Background(), opts(srv.URL))
	for _, c := range r.Checks {
		switch c.ID {
		case "past-eof":
			if c.Skip == nil || c.Skip.ID != "SKIP_OVERFLOW" {
				t.Errorf("past-eof must be skipped on overflow, got %s %+v", c.Status, c.Findings)
			}
		case "unsatisfiable":
			if c.Status != model.KindPass {
				t.Errorf("unsatisfiable: %s %+v", c.Status, c.Findings)
			}
		default:
			if c.Status != model.KindPass {
				t.Errorf("%s: %s %+v", c.ID, c.Status, c.Findings)
			}
		}
	}
	if r.Representation.Length == nil || *r.Representation.Length != math.MaxInt64 {
		t.Errorf("length %v", r.Representation.Length)
	}
	if got := check(t, r, "tail").Request.Range; got != "bytes=9223372036854775551-9223372036854775806" {
		t.Errorf("tail range %s", got)
	}
}

func TestLengthBeyondInt64IsReportedNotWrapped(t *testing.T) {
	srv := httptest.NewServer(synthetic("18446744073709551616", 1000))
	defer srv.Close()
	r := Run(context.Background(), opts(srv.URL))
	c := check(t, r, "first-byte")
	if c.Status != model.KindInconclusive || !hasFinding(c, "NUMBER_OUT_OF_RANGE") {
		t.Errorf("%s %+v", c.Status, c.Findings)
	}
	if r.Representation.Length != nil {
		t.Error("an unrepresentable length must not be adopted")
	}
	if r.Summary.ExitCode == model.ExitPass {
		t.Error("must not pass")
	}
}

func TestSecretsNeverReachReport(t *testing.T) {
	h := &testsrv.Handler{Data: testsrv.Content(fileSize), ETag: `"v1"`}
	r := probeServer(t, h, true, func(o *Options) {
		o.Headers = http.Header{"Authorization": {"Bearer TOPSECRETTOKEN"}, "X-Api-Key": {"KEY12345"}}
	})
	b := fmt.Sprintf("%+v", r)
	for _, bad := range []string{"TOPSECRETTOKEN", "KEY12345", "SECRETSIG"} {
		if strings.Contains(b, bad) {
			t.Errorf("%q leaked into the report", bad)
		}
	}
	if !strings.Contains(r.Run.Target, "sig=REDACTED") {
		t.Errorf("target %s", r.Run.Target)
	}
	for _, c := range h.Requests() {
		if c.Header.Get("Authorization") != "Bearer TOPSECRETTOKEN" {
			t.Error("the header must still be sent to the target")
		}
	}
	_ = io.EOF
}

func TestCrossOriginRedirectKeepsCredentialsAway(t *testing.T) {
	data := testsrv.Content(fileSize)
	var seen atomic.Value
	cdn := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen.Store(r.Header.Clone())
		(&testsrv.Handler{Data: data, ETag: `"v1"`}).ServeHTTP(w, r)
	}))
	defer cdn.Close()
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, cdn.URL+"/blob?sig=abc", http.StatusFound)
	}))
	defer front.Close()
	o := opts(front.URL + "/file")
	o.Headers = http.Header{"Authorization": {"Bearer TOPSECRETTOKEN"}}
	o.Ref = refFile(t, data)
	r := Run(context.Background(), o)
	allChecks(t, r, model.KindPass)
	if h, _ := seen.Load().(http.Header); h.Get("Authorization") != "" {
		t.Errorf("credentials followed the redirect: %v", h)
	}
	if !strings.HasPrefix(r.Endpoint.FinalURL, cdn.URL+"/blob?sig=REDACTED") {
		t.Errorf("final endpoint %q", r.Endpoint.FinalURL)
	}
	if len(r.Endpoint.Redirects) != 1 {
		t.Errorf("redirects %+v", r.Endpoint.Redirects)
	}
}

func TestReferenceChangedDuringRun(t *testing.T) {
	data := testsrv.Content(fileSize)
	h := &testsrv.Handler{Data: data, ETag: `"v1"`}
	srv := httptest.NewServer(h)
	defer srv.Close()
	ref := refFile(t, data)
	if err := os.Truncate(ref.Path(), 10); err != nil { // the user edits the reference while the probe runs
		t.Fatal(err)
	}
	o := opts(srv.URL)
	o.Ref = ref
	r := Run(context.Background(), o)
	found := false
	for _, f := range r.RunFindings {
		found = found || f.ID == "REFERENCE_CHANGED"
	}
	if !found || r.Summary.ExitCode == model.ExitPass {
		t.Errorf("found=%v exit=%d", found, r.Summary.ExitCode)
	}
}

func TestUnknownTotalLengthRunsOnlyWhatIsSafe(t *testing.T) {
	h := &testsrv.Handler{Data: testsrv.Content(fileSize), ETag: `"v1"`}
	h.Tamper = func(r *testsrv.Reply) {
		if r.Start >= 0 { // RFC 9110 14.4: the length may be unknown ("*")
			r.Header.Set("Content-Range", fmt.Sprintf("bytes %d-%d/*", r.Start, r.End))
		}
	}
	r := probeServer(t, h, false, nil)
	if r.Representation.Length != nil {
		t.Errorf("no length was reported: %v", *r.Representation.Length)
	}
	for _, id := range []string{"middle", "tail", "open-ended", "past-eof", "overlap"} {
		if c := check(t, r, id); c.Skip == nil || c.Skip.ID != "SKIP_SIZE_UNKNOWN" {
			t.Errorf("%s must be skipped for lack of a length: %+v", id, c.Skip)
		}
	}
	if c := check(t, r, "unsatisfiable"); c.Skip == nil || c.Skip.ID != "SKIP_REMOTE_SIZE" {
		t.Errorf("unsatisfiable: %+v", c.Skip)
	}
	for _, id := range []string{"first-byte", "head", "suffix", "reread"} {
		wantStatus(t, r, id, model.KindPass)
	}
	if r.Summary.ExitCode != model.ExitIncomplete {
		t.Errorf("skipped key checks must prevent a PASS: exit %d", r.Summary.ExitCode)
	}
}

func TestHostileHeadersCannotInjectMarkup(t *testing.T) {
	h := &testsrv.Handler{Data: testsrv.Content(fileSize), ETag: `"<img src=x onerror=alert(1)>"`}
	h.Tamper = func(r *testsrv.Reply) {
		r.Header.Set("Server", "<script>alert(1)</script>‮")
		r.Header.Set("Content-Type", "text/html; x=<b>")
	}
	r := probeServer(t, h, true, nil)
	fp := ""
	for _, c := range r.Checks {
		if c.Response != nil {
			for _, kv := range c.Response.Headers {
				fp += kv.Value
			}
		}
	}
	if strings.Contains(fp, "‮") {
		t.Error("bidi control survived in recorded header values")
	}
}
