// Package interpret turns recorded exchanges into findings. It separates what
// was observed from what may be concluded: every finding names the
// conditions it needs and the limits of what it proves.
package interpret

import (
	"errors"
	"fmt"
	"mime"
	"strings"

	"github.com/0then0/rangeprobe/internal/capture"
	"github.com/0then0/rangeprobe/internal/model"
	"github.com/0then0/rangeprobe/internal/rangespec"
	"github.com/0then0/rangeprobe/internal/redact"
	"github.com/0then0/rangeprobe/internal/transport"
)

// RemoteSize is a representation length reported by the server.
type RemoteSize struct {
	Known bool
	Value int64
	// Basis names the source: "content-range", "content-length-200".
	Basis string
}

// Params is the context of one probe.
type Params struct {
	Spec     rangespec.Spec
	RefSize  *int64 // reference length; nil in observe mode
	Remote   RemoteSize
	Baseline *Fingerprint
	IfMatch  bool
}

// BodyMode says how the body should be consumed.
type BodyMode int

// Body modes.
const (
	BodyNone    BodyMode = iota // do not read
	BodyDiscard                 // read a small prefix, no comparison
	BodyPartial                 // 206 with a usable Content-Range
	BodyFull                    // 200 to a range request
)

// HeadAnalysis is the verdict on status line and headers, produced before
// the body is read because it decides how the body is consumed.
type HeadAnalysis struct {
	P          Params
	Head       *transport.Head
	Mode       BodyMode
	First      int64 // declared interval for BodyPartial
	Last       int64
	Want       int64 // expected body length, -1 if unknown
	EncodingOK bool
	FP         Fingerprint
	Findings   []model.Finding

	refSizeMismatch bool
	crRaw           string
}

// Declared reports the length of the declared interval for BodyPartial.
func (a *HeadAnalysis) Declared() int64 { return a.Last - a.First + 1 }

func clean(s string) string { return redact.Clean(s, 200) }

func (a *HeadAnalysis) add(f model.Finding) { a.Findings = append(a.Findings, f) }

// AnalyzeHead evaluates the response head against the request.
func AnalyzeHead(p Params, h *transport.Head) *HeadAnalysis {
	a := &HeadAnalysis{P: p, Head: h, Want: -1}
	enc := strings.ToLower(strings.TrimSpace(h.Header.Get("Content-Encoding")))
	if enc == "" {
		enc = "identity"
	}
	a.EncodingOK = enc == "identity"
	if et := h.Header.Get("ETag"); et != "" {
		a.FP.HasETag, a.FP.ETag = true, clean(et)
		a.FP.ETagWeak = strings.HasPrefix(et, "W/") || !strings.HasPrefix(et, `"`)
	}
	a.FP.LastModified = clean(h.Header.Get("Last-Modified"))

	switch h.Status {
	case 206:
		a.FP.Encoding = enc
		a.analyze206()
	case 200:
		a.FP.Encoding = enc
		a.analyze200()
	case 416:
		a.analyze416()
	case 412:
		if p.IfMatch {
			a.add(model.NewFinding("PRECONDITION_FAILED", "server answered 412 to If-Match with the ETag seen earlier",
				model.Ev("status", 412), model.Ev("if_match", "sent")).
				WithLimits("The representation may have changed, or the server evaluates If-Match differently from the ETag it sent."))
			break
		}
		a.unexpected()
	case 408, 429, 500, 501, 502, 503, 504, 505, 506, 507, 508, 510, 511:
		a.add(model.NewFinding("HTTP_SERVER_ERROR", fmt.Sprintf("server answered %d", h.Status),
			model.Ev("status", h.Status), model.Ev("retry_after", clean(h.Header.Get("Retry-After")))))
		a.Mode = BodyDiscard
	default:
		a.unexpected()
	}
	if !a.EncodingOK && (h.Status == 200 || h.Status == 206) {
		a.add(model.NewFinding("ENCODING_UNSUPPORTED",
			"server applied a content coding although identity was requested; encoded bytes are not compared",
			model.Ev("content_encoding", clean(enc))).
			WithLimits("Byte equality with the reference is not evaluated. Structural checks still apply."))
	}
	return a
}

func (a *HeadAnalysis) unexpected() {
	st := a.Head.Status
	msg := fmt.Sprintf("status %d does not allow a range verdict", st)
	var lim string
	switch st {
	case 401, 403:
		lim = "Access was refused; supply credentials with --header or --header-file if the endpoint needs them."
	case 404, 410:
		lim = "The URL did not resolve to a representation."
	default:
		lim = "Only 200, 206 and 416 are evaluated."
	}
	a.add(model.NewFinding("HTTP_STATUS_UNEXPECTED", msg, model.Ev("status", st), model.Ev("location", clean(a.Head.Header.Get("Location")))).WithLimits(lim))
	a.Mode = BodyDiscard
}

func (a *HeadAnalysis) analyze206() {
	h := a.Head
	if mt, _, err := mime.ParseMediaType(h.Header.Get("Content-Type")); err == nil && mt == "multipart/byteranges" {
		a.add(model.NewFinding("MULTIPART_UNSUPPORTED",
			"single-range request was answered with multipart/byteranges; the body is not parsed",
			model.Ev("content_type", clean(h.Header.Get("Content-Type")))).
			WithLimits("RangeProbe v0.1 parses only single-part 206 responses."))
		return
	}
	vals := h.Header.Values("Content-Range")
	switch len(vals) {
	case 0:
		a.add(model.NewFinding("STATUS_206_NO_CONTENT_RANGE", "206 response without Content-Range",
			model.Ev("status", 206), model.Ev("content_type", clean(h.Header.Get("Content-Type")))))
		return
	case 1:
	default:
		a.add(model.NewFinding("CONTENT_RANGE_INVALID", "Content-Range is repeated",
			model.Ev("count", len(vals)), model.Ev("values", clean(strings.Join(vals, " | ")))))
		return
	}
	a.crRaw = vals[0]
	cr, err := rangespec.ParseContentRange(vals[0])
	if err != nil {
		a.badCR(err, vals[0])
		return
	}
	if cr.Unsatisfied {
		a.add(model.NewFinding("CONTENT_RANGE_INVALID", "unsatisfied-range form in a 206 response",
			model.Ev("content_range", clean(vals[0]))))
		return
	}
	a.Mode, a.First, a.Last, a.Want = BodyPartial, cr.First, cr.Last, cr.Len()
	if cr.TotalKnown {
		a.FP.Total, a.FP.TotalKnown = cr.Total, true
		a.checkRefSize(cr.Total)
	}
	req := a.P.Spec.Header()
	switch {
	case cr.TotalKnown:
		f, l, ok := a.P.Spec.Resolve(cr.Total)
		switch {
		case !ok:
			a.add(model.NewFinding("UNSATISFIABLE_GOT_206", "206 returned for a range that is unsatisfiable under the reported length",
				model.Ev("request_range", req), model.Ev("content_range", clean(vals[0]))))
		case cr.First < f || cr.Last > l:
			a.add(model.NewFinding("CONTENT_RANGE_OUTSIDE_REQUEST", "Content-Range is not inside the interval the request selects",
				model.Ev("request_range", req), model.Ev("content_range", clean(vals[0])),
				model.Ev("expected_interval", fmt.Sprintf("%d-%d", f, l))))
		case cr.First != f || cr.Last != l:
			a.add(model.NewFinding("PARTIAL_RESPONSE", "206 covers only part of the requested range",
				model.Ev("request_range", req), model.Ev("content_range", clean(vals[0])),
				model.Ev("expected_interval", fmt.Sprintf("%d-%d", f, l))))
		}
	default:
		s := a.P.Spec
		outside := (s.Kind == rangespec.KindInt && (cr.First < s.First || cr.Last > s.Last)) ||
			(s.Kind == rangespec.KindOpen && cr.First < s.First)
		if outside {
			a.add(model.NewFinding("CONTENT_RANGE_OUTSIDE_REQUEST", "Content-Range is not inside the requested range",
				model.Ev("request_range", req), model.Ev("content_range", clean(vals[0]))))
		}
	}
	if h.ContentLength >= 0 && h.ContentLength != a.Want {
		a.add(model.NewFinding("CONTENT_LENGTH_RANGE_MISMATCH", "Content-Length differs from the Content-Range interval length",
			model.Ev("content_length", h.ContentLength), model.Ev("content_range", clean(vals[0])),
			model.Ev("interval_length", a.Want)))
	}
}

func (a *HeadAnalysis) badCR(err error, raw string) {
	switch {
	case errors.Is(err, rangespec.ErrNumberRange):
		a.add(model.NewFinding("NUMBER_OUT_OF_RANGE", "Content-Range contains a number above 9223372036854775807",
			model.Ev("content_range", clean(raw))).
			WithLimits("The value is syntactically valid; RangeProbe cannot compute with it, so no verdict is given."))
	default:
		a.add(model.NewFinding("CONTENT_RANGE_INVALID", "Content-Range is not valid: "+err.Error(),
			model.Ev("content_range", clean(raw))))
	}
}

func (a *HeadAnalysis) analyze200() {
	h := a.Head
	ev := []model.KV{
		model.Ev("request_range", a.P.Spec.Header()), model.Ev("status", 200),
		model.Ev("accept_ranges", orNone(clean(h.Header.Get("Accept-Ranges")))),
		model.Ev("content_length", lengthStr(h.ContentLength)),
	}
	a.add(model.NewFinding("RANGE_IGNORED", "server returned the full representation instead of a partial response", ev...).
		WithLimits("RFC 9110 14.2 allows servers to ignore Range. This only means random access is unavailable here.",
			"Behaviour for other ranges or conditions is not implied."))
	a.Mode = BodyFull
	if len(h.Header.Values("Content-Range")) > 0 {
		a.add(model.NewFinding("FULL_RESPONSE_CONTENT_RANGE", "Content-Range present on a 200 response",
			model.Ev("content_range", clean(h.Header.Get("Content-Range")))))
	}
	if h.ContentLength >= 0 {
		a.Want = h.ContentLength
		a.FP.Total, a.FP.TotalKnown = h.ContentLength, true
		a.checkRefSize(h.ContentLength)
	}
}

func (a *HeadAnalysis) analyze416() {
	a.Mode = BodyDiscard
	vals := a.Head.Header.Values("Content-Range")
	if len(vals) == 0 {
		a.add(model.NewFinding("RANGE_416_CONTENT_RANGE_MISSING", "416 without Content-Range", model.Ev("status", 416)))
		a.unknown416()
		return
	}
	if len(vals) > 1 {
		a.add(model.NewFinding("CONTENT_RANGE_INVALID", "Content-Range is repeated", model.Ev("count", len(vals))))
		return
	}
	cr, err := rangespec.ParseContentRange(vals[0])
	if err != nil {
		a.badCR(err, vals[0])
		return
	}
	if !cr.Unsatisfied {
		a.add(model.NewFinding("CONTENT_RANGE_INVALID", "416 response carries a satisfied-range Content-Range",
			model.Ev("content_range", clean(vals[0]))))
		return
	}
	a.FP.Total, a.FP.TotalKnown = cr.Total, true
	a.checkRefSize(cr.Total)
	if _, _, ok := a.P.Spec.Resolve(cr.Total); ok {
		a.add(model.NewFinding("SATISFIABLE_GOT_416", "416 returned although the range is satisfiable under the length the response reports",
			model.Ev("request_range", a.P.Spec.Header()), model.Ev("content_range", clean(vals[0]))))
	}
}

func (a *HeadAnalysis) unknown416() {
	if a.P.Remote.Known {
		if _, _, ok := a.P.Spec.Resolve(a.P.Remote.Value); ok {
			a.add(model.NewFinding("UNEXPECTED_416", "416 without Content-Range for a range that is satisfiable under the earlier reported length",
				model.Ev("request_range", a.P.Spec.Header()), model.Ev("earlier_length", a.P.Remote.Value)).
				WithLimits("The representation may have shrunk since the length was observed."))
		}
	}
}

func (a *HeadAnalysis) checkRefSize(total int64) {
	if a.P.RefSize != nil && *a.P.RefSize != total {
		a.refSizeMismatch = true
		a.add(model.NewFinding("REFERENCE_SIZE_MISMATCH", "the server reports a different length than the reference file",
			model.Ev("server_length", total), model.Ev("reference_length", *a.P.RefSize)).
			WithLimits("The reference is probably a different file or version. Byte comparisons for this run cannot support conclusions about Range handling."))
	}
}

func orNone(s string) string {
	if s == "" {
		return "(absent)"
	}
	return s
}

func lengthStr(n int64) string {
	if n < 0 {
		return "(absent)"
	}
	return fmt.Sprint(n)
}

// BodyState summarises how the body ended.
type BodyState struct {
	// Complete means the whole declared body was received and its end
	// verified (or could not be probed for lack of budget).
	Complete bool
	// End is one of complete, truncated, excess, limit, error, unread,
	// prefix.
	End string
	// ExtraProbed is true when one octet beyond the declared length could
	// be requested.
	ExtraProbed bool
}

// Finish evaluates the body after reading. sink may be nil when the body
// was not read.
func (a *HeadAnalysis) Finish(ex *transport.Exchange, sink *capture.Sink, ref bool) ([]model.Finding, BodyState) {
	st := BodyState{End: "unread"}
	var fs []model.Finding
	fs = append(fs, a.Findings...)
	fs = a.bodyFindings(fs, ex, &st)
	if sink != nil && ref && a.EncodingOK && (a.Mode == BodyPartial || a.Mode == BodyFull) {
		fs = a.compareFindings(fs, sink)
	}
	return fs, st
}

func (a *HeadAnalysis) bodyFindings(fs []model.Finding, ex *transport.Exchange, st *BodyState) []model.Finding {
	switch a.Mode {
	case BodyPartial, BodyFull:
	case BodyDiscard:
		st.End = "discarded"
		return fs
	default:
		return fs
	}
	bf := ex.BodyFail
	if bf != nil {
		if bf.Kind == transport.FailTruncated {
			st.End = "truncated"
			return append(fs, a.truncated(ex))
		}
		st.End = "error"
		return append(fs, bodyFailure(bf, ex))
	}
	if a.Mode == BodyFull {
		switch {
		case ex.EOF && a.Want >= 0 && ex.Read < a.Want:
			st.End = "truncated"
			return append(fs, a.truncated(ex))
		case ex.EOF:
			st.End, st.Complete = "complete", true
		default:
			st.End = "prefix"
		}
		return fs
	}
	// BodyPartial.
	L := a.Want
	switch {
	case ex.Read > L:
		st.End = "excess"
		return append(fs, model.NewFinding("BODY_EXCESS", "body continues beyond the Content-Range length",
			model.Ev("declared_length", L), model.Ev("received_at_least", ex.Read),
			model.Ev("content_range", clean(a.crRaw)), model.Ev("chunked", a.Head.Chunked)).
			WithLimits("Only one octet beyond the declared length is read; the true surplus is unknown."))
	case ex.EOF && ex.Read < L:
		st.End = "truncated"
		return append(fs, a.truncated(ex))
	case ex.Read == L && ex.EOF:
		st.End, st.Complete, st.ExtraProbed = "complete", true, true
	case ex.Read == L:
		st.End, st.Complete = "complete", true
		fs = append(fs, model.NewFinding("EXTRA_BYTE_CHECK_SKIPPED", "no budget to read one octet past the declared length",
			model.Ev("declared_length", L), model.Ev("read_limit", ex.Limit)))
	default:
		st.End = "limit"
		fs = append(fs, model.NewFinding("BODY_LIMIT_REACHED", "reading stopped at a limit before the declared length",
			model.Ev("declared_length", L), model.Ev("bytes_read", ex.Read), model.Ev("read_limit", ex.Limit)).
			WithLimits("The unread tail of the body is unverified."))
	}
	return fs
}

func (a *HeadAnalysis) truncated(ex *transport.Exchange) model.Finding {
	want := fmt.Sprint(a.Want)
	if a.Want < 0 {
		want = "(unknown)"
	}
	return model.NewFinding("BODY_TRUNCATED", "the body ended before the declared length",
		model.Ev("status", a.Head.Status), model.Ev("declared_length", want), model.Ev("bytes_read", ex.Read),
		model.Ev("content_length", lengthStr(a.Head.ContentLength)), model.Ev("content_range", orNone(clean(a.crRaw))),
		model.Ev("chunked", a.Head.Chunked)).
		WithLimits("A proxy, load balancer or network fault can end a stream early as well; repeat the run to see whether it is deterministic.")
}

func bodyFailure(bf *transport.Failure, ex *transport.Exchange) model.Finding {
	id := "BODY_READ_ERROR"
	switch bf.Kind {
	case transport.FailTimeout, transport.FailRunTimeout:
		id = "REQUEST_TIMEOUT"
	case transport.FailCancelled:
		id = "CANCELLED"
	}
	return model.NewFinding(id, "reading the body failed: "+bf.Message, model.Ev("bytes_read", ex.Read))
}

// FailureFinding converts a request-level failure into a finding.
func FailureFinding(f *transport.Failure) model.Finding {
	id := "REQUEST_FAILED"
	switch f.Kind {
	case transport.FailTimeout, transport.FailRunTimeout:
		id = "REQUEST_TIMEOUT"
	case transport.FailCancelled:
		id = "CANCELLED"
	case transport.FailRedirectRefused:
		id = "REDIRECT_REFUSED"
	case transport.FailRedirectLimit:
		id = "REDIRECT_LIMIT"
	}
	return model.NewFinding(id, f.Message)
}

func (a *HeadAnalysis) compareFindings(fs []model.Finding, sink *capture.Sink) []model.Finding {
	r := sink.Result()
	if r.RefErr != nil {
		return append(fs, model.NewFinding("REFERENCE_CHANGED", "the reference file could not be read completely: "+clean(r.RefErr.Error())))
	}
	if r.MismatchCount == 0 {
		return fs
	}
	ev := []model.KV{
		model.Ev("first_mismatch_offset", r.FirstMismatch), model.Ev("mismatching_bytes", r.MismatchCount),
		model.Ev("compared_bytes", r.Compared), model.Ev("observed_sha256", sink.SHA256()),
		model.Ev("expected_sha256", sink.ExpectedSHA256()),
	}
	if r.BeyondReference > 0 {
		ev = append(ev, model.Ev("bytes_beyond_reference", r.BeyondReference))
	}
	if r.ShiftHint != "" {
		ev = append(ev, model.Ev("shift_hint", r.ShiftHint))
	}
	msg := "response bytes differ from the reference slice"
	if a.Mode == BodyFull {
		msg = "the prefix of the full response differs from the reference"
	}
	f := model.NewFinding("BYTES_MISMATCH_REFERENCE", msg, ev...).WithLimits(
		"This is an observed difference, not a diagnosis. The reference may be a different file or version than the published one.",
		"It does not by itself show that the server's Range handling is defective.").AsIdentity()
	if a.refSizeMismatch {
		f = f.Downgrade("The reference length differs from the length the server reports, so the files are not known to match.")
		f.Identity = false
	}
	return append(fs, f)
}

// Verified lists the claims that held for a passing check.
func (a *HeadAnalysis) Verified(ref bool, sink *capture.Sink) []string {
	var out []string
	switch a.Head.Status {
	case 206:
		if a.Mode != BodyPartial {
			return nil
		}
		out = append(out,
			fmt.Sprintf("206 with Content-Range %d-%d consistent with request %s", a.First, a.Last, a.P.Spec.Header()),
			fmt.Sprintf("body length equals the declared interval length (%d bytes), no excess octet seen", a.Declared()))
		if ref && a.EncodingOK && sink != nil {
			out = append(out, fmt.Sprintf("bytes %d-%d equal the reference file's bytes %d-%d (%d bytes compared, sha256 %s)",
				a.First, a.Last, a.First, a.Last, sink.Result().Compared, short(sink.SHA256())))
		}
	case 416:
		if a.FP.TotalKnown {
			out = append(out, fmt.Sprintf("416 with Content-Range bytes */%d, consistent with an unsatisfiable range %s", a.FP.Total, a.P.Spec.Header()))
		} else {
			out = append(out, "416 for the unsatisfiable range (no usable Content-Range)")
		}
	}
	return out
}

func short(s string) string {
	if len(s) > 16 {
		return s[:16] + "…"
	}
	return s
}

// Retained is a complete 206 body kept for consistency comparisons.
type Retained struct {
	First, Last int64
	Body        []byte
	FP          Fingerprint
}

// RelationKind selects the comparison.
type RelationKind string

// Relation kinds.
const (
	RelOverlap RelationKind = "overlap"
	RelReread  RelationKind = "reread"
)

// Relate compares two retained bodies on their common interval.
func Relate(kind RelationKind, a, b *Retained) (fs []model.Finding, verified []string) {
	if a == nil || b == nil {
		return []model.Finding{model.NewFinding("RELATION_INPUT_UNAVAILABLE", "the earlier or the current response did not yield a complete 206 body to compare")}, nil
	}
	lo, hi := max(a.First, b.First), min(a.Last, b.Last)
	if hi < lo {
		return []model.Finding{model.NewFinding("RELATION_INPUT_UNAVAILABLE", "the two intervals do not overlap")}, nil
	}
	ev, why := Compare(a.FP, b.FP)
	window := model.Ev("compared_interval", fmt.Sprintf("%d-%d", lo, hi))
	if ev == EvidenceConflict {
		return []model.Finding{model.NewFinding("REPRESENTATION_CHANGED",
			"the two responses carry conflicting representation signals; consistency cannot be judged",
			model.Ev("reasons", strings.Join(why, "; ")), window)}, nil
	}
	sa := a.Body[lo-a.First : hi-a.First+1]
	sb := b.Body[lo-b.First : hi-b.First+1]
	equal := string(sa) == string(sb)
	if equal {
		verified = append(verified, fmt.Sprintf("bytes %d-%d are identical in two separate responses (%s); this shows consistency, not correctness", lo, hi, kind))
		if ev == EvidenceWeak {
			fs = append(fs, model.NewFinding("WEAK_VALIDATORS", "responses agree, but no shared strong ETag establishes that they describe one representation",
				window, model.Ev("evidence", ev.String())))
		}
		return fs, verified
	}
	id, msg := "OVERLAP_INCONSISTENT", "overlapping ranges returned different bytes"
	if kind == RelReread {
		id, msg = "REREAD_INCONSISTENT", "re-reading the same range returned different bytes"
	}
	first := int64(0)
	for first < int64(len(sa)) && sa[first] == sb[first] {
		first++
	}
	evd := []model.KV{window, model.Ev("first_difference_offset", lo+first), model.Ev("evidence", ev.String())}
	if ev == EvidenceStrong {
		return []model.Finding{model.NewFinding(id, msg+" under the same strong ETag", evd...).
			WithLimits("Assumes the server's strong ETag is accurate; a server that reuses an ETag for changed content produces the same symptom.")}, nil
	}
	return []model.Finding{model.NewFinding("CONSISTENCY_UNATTRIBUTED", msg+", but one representation is not established", evd...).
		WithLimits("Without a shared strong ETag the difference may come from a changed file rather than a Range defect.")}, nil
}

// ApplyStability compares fp with the baseline and, on conflict, adds
// REPRESENTATION_CHANGED and downgrades findings that rely on identity.
func ApplyStability(fs []model.Finding, baseline *Fingerprint, fp Fingerprint) []model.Finding {
	if baseline == nil {
		return fs
	}
	ev, why := Compare(*baseline, fp)
	if ev != EvidenceConflict {
		return fs
	}
	out := make([]model.Finding, 0, len(fs)+1)
	for _, f := range fs {
		if f.Identity {
			f = f.Downgrade("Representation signals changed during the run (" + strings.Join(why, "; ") + "), so the reference or earlier answers may no longer describe this response.")
		}
		out = append(out, f)
	}
	return append(out, model.NewFinding("REPRESENTATION_CHANGED", "representation signals differ from the first response of this run",
		model.Ev("reasons", strings.Join(why, "; "))).
		WithLimits("A changed ETag, length or Last-Modified is not a Range defect by itself; the file may have been replaced during the run."))
}
