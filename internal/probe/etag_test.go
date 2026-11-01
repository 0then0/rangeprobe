package probe

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/0then0/rangeprobe/internal/model"
	"github.com/0then0/rangeprobe/internal/report"
	"github.com/0then0/rangeprobe/internal/testsrv"
)

// longStrongETag returns a syntactically valid strong entity-tag whose first
// 240 opaque characters are shared by every suffix and whose length is 246
// octets, well above the 200 runes a report shows.
func longStrongETag(suffix string) string {
	return `"` + strings.Repeat("x", 240) + suffix + `"`
}

// flipped returns a copy of b that differs at every octet.
func flipped(b []byte) []byte {
	out := make([]byte, len(b))
	for i := range b {
		out[i] = b[i] ^ 0x5A
	}
	return out
}

// changingResource serves one resource that is replaced after the first
// switchAfter requests: same length, new bytes, new ETag.
func changingResource(t *testing.T, etagBefore, etagAfter string, switchAfter int32) (*httptest.Server, *testsrv.Handler) {
	t.Helper()
	data := testsrv.Content(fileSize)
	before := &testsrv.Handler{Data: data, ETag: etagBefore}
	after := &testsrv.Handler{Data: flipped(data), ETag: etagAfter}
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if n.Add(1) > switchAfter {
			after.ServeHTTP(w, r)
			return
		}
		before.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv, before
}

func runObserve(t *testing.T, url string, mod func(*Options)) *model.Report {
	t.Helper()
	o := opts(url + "/data.bin")
	if mod != nil {
		mod(&o)
	}
	return Run(t.Context(), o)
}

func noRelationViolation(t *testing.T, r *model.Report) {
	t.Helper()
	for _, id := range []string{"overlap", "reread"} {
		c := check(t, r, id)
		if c.Status == model.KindViolation || hasFinding(c, "OVERLAP_INCONSISTENT") || hasFinding(c, "REREAD_INCONSISTENT") {
			t.Errorf("%s: false violation: %s %+v", id, c.Status, c.Findings)
		}
		if !hasFinding(c, "REPRESENTATION_CHANGED") {
			t.Errorf("%s: change of representation not recognised: %s %+v", id, c.Status, c.Findings)
		}
	}
	if r.Summary.Result == model.ResultProblem {
		t.Errorf("a replaced resource must not be reported as a problem: %+v", r.Summary)
	}
	if r.Summary.ExitCode != model.ExitIncomplete {
		t.Errorf("exit code %d, want %d", r.Summary.ExitCode, model.ExitIncomplete)
	}
	if r.Representation.Stable {
		t.Error("representation reported as stable")
	}
}

// Scenario A: short strong ETags that differ.
func TestChangingResourceShortETags(t *testing.T) {
	srv, _ := changingResource(t, `"v1"`, `"v2"`, 3)
	noRelationViolation(t, runObserve(t, srv.URL, nil))
}

// Scenario B: long strong ETags that differ only in the last four octets.
// Truncating them for display must not make them equal.
func TestChangingResourceLongETagsSharingPrefix(t *testing.T) {
	srv, _ := changingResource(t, longStrongETag("0001"), longStrongETag("0002"), 3)
	noRelationViolation(t, runObserve(t, srv.URL, nil))

	// The same replacement seen against a reference file is not a Range defect.
	srv2, _ := changingResource(t, longStrongETag("0001"), longStrongETag("0002"), 3)
	rr := runObserve(t, srv2.URL, func(o *Options) { o.Ref = refFile(t, testsrv.Content(fileSize)) })
	if rr.Summary.Result == model.ResultProblem {
		t.Errorf("reference mode: replaced resource reported as a problem: %+v", rr.Summary)
	}
	if rr.Summary.ExitCode != model.ExitIncomplete {
		t.Errorf("reference mode: exit code %d", rr.Summary.ExitCode)
	}
}

// ifMatchMustEqual makes the server answer 412 to any If-Match that is not
// byte-for-byte the given ETag, as RFC 9110 13.1.1 requires of a server
// whose current representation carries that strong ETag.
func ifMatchMustEqual(etag string) func(*testsrv.Reply) {
	return func(r *testsrv.Reply) {
		if im, ok := r.Req.Header["If-Match"]; ok && (len(im) != 1 || im[0] != etag) {
			r.Status, r.Body = http.StatusPreconditionFailed, nil
			r.Header.Del("Content-Range")
		}
	}
}

// Scenario C: unchanged resource, one long strong ETag, no preconditions.
func TestUnchangedResourceLongETag(t *testing.T) {
	etag := longStrongETag("0001")
	h := &testsrv.Handler{Data: testsrv.Content(fileSize), ETag: etag}
	r := probeServer(t, h, true, nil)
	allChecks(t, r, model.KindPass)
	if r.Summary.ExitCode != model.ExitPass {
		t.Errorf("exit code %d: %+v", r.Summary.ExitCode, r.Summary)
	}
	if r.Representation.ETagStrength != "strong" || !r.Representation.Stable {
		t.Errorf("representation %+v", r.Representation)
	}
	for _, l := range h.Requests() {
		if _, ok := l.Header["If-Match"]; ok {
			t.Error("If-Match sent without --preconditions")
		}
	}
}

// Scenario D: the same resource with --preconditions. The server rejects any
// If-Match that differs from its ETag, so success proves the full value was sent.
func TestPreconditionsSendTheCompleteLongETag(t *testing.T) {
	etag := longStrongETag("0001")
	h := &testsrv.Handler{Data: testsrv.Content(fileSize), ETag: etag}
	h.Tamper = ifMatchMustEqual(etag)
	r := probeServer(t, h, true, func(o *Options) { o.Preconditions = true })
	allChecks(t, r, model.KindPass)
	logs := h.Requests()
	if _, ok := logs[0].Header["If-Match"]; ok {
		t.Error("the first request has no ETag to send")
	}
	for i, l := range logs[1:] {
		if got := l.Header.Values("If-Match"); len(got) != 1 || got[0] != etag {
			t.Fatalf("request %d: If-Match = %q, want exactly the server's ETag", i+1, got)
		}
	}
}

// Scenario E: one strong ETag, different bytes. The violations stay.
func TestSameLongETagDifferentBytesStillViolates(t *testing.T) {
	etag := longStrongETag("0001")
	h := &testsrv.Handler{Data: testsrv.Content(fileSize), ETag: etag}
	var rereads atomic.Int32
	h.Tamper = func(r *testsrv.Reply) {
		flip := false
		switch r.Range {
		case "bytes=10000-10255": // overlap: wrong octets inside the shared window
			flip = true
		case "bytes=9872-10127": // middle, then re-read: the second answer differs
			flip = rereads.Add(1) == 2
		}
		if flip {
			b := append([]byte(nil), r.Body...)
			b[5] ^= 0xFF
			r.Body = b
		}
	}
	r := probeServer(t, h, false, nil)
	if c := check(t, r, "overlap"); c.Status != model.KindViolation || !hasFinding(c, "OVERLAP_INCONSISTENT") {
		t.Errorf("overlap: %s %+v", c.Status, c.Findings)
	}
	if c := check(t, r, "reread"); c.Status != model.KindViolation || !hasFinding(c, "REREAD_INCONSISTENT") {
		t.Errorf("reread: %s %+v", c.Status, c.Findings)
	}
	if r.Summary.Result != model.ResultProblem {
		t.Errorf("result %s", r.Summary.Result)
	}
}

// ETag octets 0x80-0xFF are legal (obs-text). They must take part in
// comparison and If-Match unchanged, whether or not they form UTF-8.
func TestObsTextETagIsUsedVerbatim(t *testing.T) {
	for _, etag := range []string{"\"caf\xc3\xa9\"", "\"caf\xe9-\xff\x80\""} {
		h := &testsrv.Handler{Data: testsrv.Content(fileSize), ETag: etag}
		h.Tamper = ifMatchMustEqual(etag)
		r := probeServer(t, h, true, func(o *Options) { o.Preconditions = true })
		allChecks(t, r, model.KindPass)
		if r.Representation.ETagStrength != "strong" {
			t.Errorf("%q: strength %q", etag, r.Representation.ETagStrength)
		}
		for i, l := range h.Requests()[1:] {
			if got := l.Header.Values("If-Match"); len(got) != 1 || got[0] != etag {
				t.Fatalf("%q: request %d sent If-Match %q", etag, i+1, got)
			}
		}
	}

	// Different octets are different tags even when they look alike once decoded.
	srv, _ := changingResource(t, "\"\xc3\xa9\"", "\"\xe9\"", 3)
	noRelationViolation(t, runObserve(t, srv.URL, nil))
}

// rereadDiffers serves a stable file whose re-read of the middle range
// differs, so that the verdict depends only on how strong the ETag is.
func rereadDiffers(set func(http.Header)) *testsrv.Handler {
	h := &testsrv.Handler{Data: testsrv.Content(fileSize)}
	var middle atomic.Int32
	h.Tamper = func(r *testsrv.Reply) {
		set(r.Header)
		if r.Range == "bytes=9872-10127" && middle.Add(1) == 2 {
			b := append([]byte(nil), r.Body...)
			b[7] ^= 0xFF
			r.Body = b
		}
	}
	return h
}

// A repeated, malformed or oversize ETag is not a validator: it creates no
// strong evidence and is never sent in If-Match.
func TestUnusableETagIsNeitherStrongEvidenceNorIfMatch(t *testing.T) {
	cases := []struct {
		name    string
		set     func(http.Header)
		problem string
	}{
		{"repeated, same value", func(h http.Header) { h["Etag"] = []string{`"v1"`, `"v1"`} }, "repeated"},
		{"repeated, different values", func(h http.Header) { h["Etag"] = []string{`"v1"`, `"v2"`} }, "repeated"},
		{"unquoted", func(h http.Header) { h.Set("ETag", `v1`) }, "malformed"},
		{"opening quote only", func(h http.Header) { h.Set("ETag", `"v1`) }, "malformed"},
		{"space inside", func(h http.Header) { h.Set("ETag", `"v 1"`) }, "malformed"},
		{"quote inside", func(h http.Header) { h.Set("ETag", `"v"1"`) }, "malformed"},
		{"trailing text", func(h http.Header) { h.Set("ETag", `"v1" x`) }, "malformed"},
		{"lowercase weak prefix", func(h http.Header) { h.Set("ETag", `w/"v1"`) }, "malformed"},
		{"oversize", func(h http.Header) { h.Set("ETag", `"`+strings.Repeat("x", 9000)+`"`) }, "too long"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := rereadDiffers(c.set)
			r := probeServer(t, h, false, func(o *Options) { o.Preconditions = true })
			if rr := check(t, r, "reread"); rr.Status != model.KindInconclusive || !hasFinding(rr, "CONSISTENCY_UNATTRIBUTED") {
				t.Errorf("reread: %s %+v", rr.Status, rr.Findings)
			}
			if r.Summary.Result == model.ResultProblem {
				t.Errorf("a problem was confirmed without a strong validator: %+v", r.Summary)
			}
			if r.Representation.ETagStrength != "none" {
				t.Errorf("strength %q", r.Representation.ETagStrength)
			}
			for _, l := range h.Requests() {
				if _, ok := l.Header["If-Match"]; ok {
					t.Fatalf("If-Match %q sent for an unusable ETag", l.Header.Values("If-Match"))
				}
			}
			var wv *model.Finding
			for i := range r.RunFindings {
				if r.RunFindings[i].ID == "WEAK_VALIDATORS" {
					wv = &r.RunFindings[i]
				}
			}
			if wv == nil {
				t.Fatal("no WEAK_VALIDATORS run finding")
			}
			got := ""
			for _, kv := range wv.Evidence {
				if kv.Key == "etag_problem" {
					got = kv.Value
				}
			}
			if got != c.problem {
				t.Errorf("etag_problem = %q, want %q", got, c.problem)
			}
		})
	}
}

// One response with an unusable ETag is neither a change of representation
// nor a reason to lose the verdicts of the others: it just compares as weak.
func TestUnusableETagDoesNotBecomeAnIdentityConflict(t *testing.T) {
	h := &testsrv.Handler{Data: testsrv.Content(fileSize), ETag: `"v1"`}
	var n atomic.Int32
	h.Tamper = func(r *testsrv.Reply) {
		if n.Add(1) == 4 { // one response lacks a usable validator
			r.Header["Etag"] = []string{`"v1"`, `"v1"`}
		}
	}
	r := probeServer(t, h, true, nil)
	if !r.Representation.Stable {
		t.Errorf("representation reported as changed: %v", r.Representation.Changes)
	}
	allChecks(t, r, model.KindPass)
}

// The complete value stays out of reports, which show it cut and escaped;
// markup and control characters in a legal ETag are neutralised.
func TestReportsShowOnlyTheSafeDisplayForm(t *testing.T) {
	etag := `"<img/src=x/onerror=alert(1)>` + strings.Repeat("x", 240) + "\xe2\x80\xae" + `0001"`
	h := &testsrv.Handler{Data: testsrv.Content(fileSize), ETag: etag}
	h.Tamper = ifMatchMustEqual(etag)
	r := probeServer(t, h, true, func(o *Options) { o.Preconditions = true })
	allChecks(t, r, model.KindPass)

	js, err := report.JSON(r)
	if err != nil || !json.Valid(js) {
		t.Fatalf("json: %v", err)
	}
	html, err := report.HTML(r)
	if err != nil {
		t.Fatal(err)
	}
	var txt strings.Builder
	report.Text(&txt, r)
	for name, out := range map[string]string{"json": string(js), "html": string(html), "text": txt.String()} {
		if strings.Contains(out, strings.Repeat("x", 240)) || strings.Contains(out, "0001\"") {
			t.Errorf("%s holds the complete ETag", name)
		}
		if strings.ContainsAny(out, "\x1b\u202e") {
			t.Errorf("%s holds an unescaped control or bidi character", name)
		}
	}
	if strings.Contains(string(html), "<img/src") {
		t.Error("html holds unescaped markup from the ETag")
	}
	if !strings.Contains(string(js), "sha256") {
		t.Error("a cut ETag should carry a digest so that long values stay distinguishable")
	}
	for _, c := range r.Checks[1:] {
		for _, kv := range c.Request.Headers {
			if kv.Key == "If-Match" && len(kv.Value) > 400 {
				t.Errorf("%s: recorded If-Match is %d long", c.ID, len(kv.Value))
			}
		}
	}
}
