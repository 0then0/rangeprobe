package probe

import (
	"bytes"
	"cmp"
	"context"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"slices"
	"strings"

	"github.com/0then0/rangeprobe/internal/interpret"
	"github.com/0then0/rangeprobe/internal/model"
	"github.com/0then0/rangeprobe/internal/rangespec"
	"github.com/0then0/rangeprobe/internal/redact"
	"github.com/0then0/rangeprobe/internal/reference"
	"github.com/0then0/rangeprobe/internal/transport"
	"github.com/0then0/rangeprobe/internal/version"
)

// ValidateMultipartRanges requires two closed ranges with a nonempty gap.
func ValidateMultipartRanges(requested [2]rangespec.Spec, size int64) error {
	for _, r := range requested {
		if r.Kind != rangespec.KindInt || !r.Valid() || r.Last >= size {
			return fmt.Errorf("both closed ranges must be within the %d-byte reference", size)
		}
	}
	lo, hi := requested[0], requested[1]
	if lo.First > hi.First {
		lo, hi = hi, lo
	}
	if hi.First-lo.Last < 2 {
		return fmt.Errorf("the two ranges must be separated by at least one byte")
	}
	return nil
}

// MaxMultipartBody bounds the buffered HTTP body of one two-range probe.
const MaxMultipartBody = 32 << 20

// Multipart observes one two-range request. The caller validates the ranges
// against ref before making the request. The body limit includes all MIME
// overhead or, for a coalesced response, the intervening representation bytes.
func Multipart(ctx context.Context, client *transport.Client, url string, ref *reference.File, requested [2]rangespec.Spec, limit int64, rd *redact.Redactor) *model.MultipartReport {
	limit = min(limit, MaxMultipartBody)
	r := &model.MultipartReport{
		SchemaVersion: 1, Mode: "multipart",
		Tool:      model.ToolInfo{Name: "rangeprobe", Version: version.Version, Repository: version.Repository},
		Reference: model.ReferenceInfo{Size: ref.Size()},
		Range:     fmt.Sprintf("bytes=%d-%d,%d-%d", requested[0].First, requested[0].Last, requested[1].First, requested[1].Last),
		BodyLimit: limit, ResponseForm: "no_response", Coverage: "unknown",
		Findings: []model.Finding{},
	}
	for i, span := range requested {
		r.Requested[i] = model.ByteInterval{First: span.First, Last: span.Last}
	}
	var body bytes.Buffer
	ex := client.Fetch(ctx, transport.Request{URL: url, Range: r.Range}, func(h *transport.Head) transport.BodyPlan {
		if h.Status == http.StatusPartialContent || h.Status == http.StatusOK {
			return transport.BodyPlan{Sink: &body, Limit: limit}
		}
		return transport.BodyPlan{}
	})
	urls := []string{url, ex.FinalURL}
	for _, h := range ex.Hops {
		urls = append(urls, h.To)
	}
	rd.SetURLQueryValues(urls...)
	r.Target = rd.ReportURL(url)
	r.Reference.Name = rd.Text(rd.Path(ref.Path()))
	if ex.FinalURL != "" {
		r.Endpoint.FinalURL = rd.ReportURL(ex.FinalURL)
	}
	for _, h := range ex.Hops {
		r.Endpoint.Redirects = append(r.Endpoint.Redirects, model.Redirect{Status: h.Status, From: rd.ReportURL(h.From), To: rd.ReportURL(h.To)})
	}
	v := multipartVerifier{ctx: ctx, report: r, ref: ref, rd: rd}
	if ex.Fail != nil {
		r.ObservationIssue = string(ex.Fail.Kind)
		if ex.Fail.Kind == transport.FailHeaderLimit {
			v.add("MULTIPART_HEADER_LIMIT", "response headers exceeded the configured limit")
		} else {
			r.Findings = append(r.Findings, interpret.FailureFinding(&transport.Failure{
				Kind: ex.Fail.Kind, Message: "request did not yield a response",
			}))
		}
	} else {
		r.Status, r.BytesRead, r.BodyComplete = ex.Head.Status, ex.Read, ex.EOF
		r.ContentType = v.clean(ex.Head.Header.Get("Content-Type"))
		r.ContentRange = v.clean(ex.Head.Header.Get("Content-Range"))
		if ex.Head.ContentLength >= 0 {
			r.ContentLength = &ex.Head.ContentLength
		}
		v.observation(ex)
		v.verify(ex.Head.Header, body.Bytes())
		if v.total != nil && *v.total != ref.Size() {
			v.add("REFERENCE_SIZE_MISMATCH", "complete representation length differs from reference size",
				model.Ev("reported_length", *v.total), model.Ev("reference_size", ref.Size()))
		}
		if ref.Changed() {
			v.add("REFERENCE_CHANGED", "reference changed during the probe")
			for i, f := range r.Findings {
				if f.Kind == model.KindByteMismatch {
					r.Findings[i] = f.Downgrade("The reference changed during the probe.")
				}
			}
		}
	}
	v.stopVerification()
	v.finish()
	return r
}

type multipartVerifier struct {
	ctx                 context.Context
	report              *model.MultipartReport
	ref                 *reference.File
	rd                  *redact.Redactor
	total               *int64
	spans               []model.ByteInterval
	lastIndex           int
	seenIndex           bool
	coalescedBytes      bool
	verificationStopped bool
}

func (v *multipartVerifier) add(id, msg string, evidence ...model.KV) {
	v.report.Findings = append(v.report.Findings, model.NewFinding(id, msg, evidence...))
}

func (v *multipartVerifier) clean(s string) string { return redact.Clean(v.rd.ReportText(s), 220) }

func (v *multipartVerifier) stopVerification() bool {
	if v.verificationStopped {
		return true
	}
	err := v.ctx.Err()
	if err == nil {
		return false
	}
	v.verificationStopped = true
	id, issue, msg := "REQUEST_TIMEOUT", string(transport.FailRunTimeout), "whole-run timeout reached during verification"
	if err == context.Canceled {
		id, issue, msg = "CANCELLED", string(transport.FailCancelled), "run cancelled during verification"
	}
	if v.report.ObservationIssue != issue {
		v.add(id, msg)
		if v.report.ObservationIssue == "" {
			v.report.ObservationIssue = issue
		}
	}
	return true
}

func (v *multipartVerifier) observation(ex *transport.Exchange) {
	r := v.report
	if ex.BodyFail != nil {
		r.ObservationIssue = string(ex.BodyFail.Kind)
		switch ex.BodyFail.Kind {
		case transport.FailTruncated:
			v.add("BODY_TRUNCATED", "HTTP stream ended before its declared framing completed")
		case transport.FailHeaderLimit:
			v.add("MULTIPART_HEADER_LIMIT", "response headers exceeded the configured limit")
		case transport.FailTimeout, transport.FailRunTimeout:
			v.add("REQUEST_TIMEOUT", "HTTP body read timed out", model.Ev("reason", ex.BodyFail.Kind))
		case transport.FailCancelled:
			v.add("CANCELLED", "HTTP body read was cancelled")
		default:
			v.add("BODY_READ_ERROR", "HTTP body read ended with an error", model.Ev("reason", ex.BodyFail.Kind))
		}
	} else if ex.Limit > 0 && !ex.EOF {
		r.ObservationIssue = "body_limit"
		v.add("MULTIPART_BODY_LIMIT", "body end was not observed within the byte limit", model.Ev("limit", ex.Limit))
	}
}

func (v *multipartVerifier) verify(header http.Header, body []byte) {
	r := v.report
	encoding := strings.TrimSpace(strings.Join(header.Values("Content-Encoding"), ","))
	identity := encoding == "" || strings.EqualFold(encoding, "identity")
	if r.Status == http.StatusOK || r.Status == http.StatusPartialContent {
		if !identity {
			v.add("ENCODING_UNSUPPORTED", "response content coding prevents comparison with the reference", model.Ev("content_encoding", v.clean(encoding)))
		}
	}
	switch r.Status {
	case http.StatusOK:
		r.ResponseForm = "full_200"
		if len(header.Values("Content-Range")) != 0 {
			v.add("FULL_RESPONSE_CONTENT_RANGE", "200 response has a Content-Range field")
		}
		v.total = r.ContentLength
		if v.total == nil && r.BodyComplete {
			v.total = &r.BytesRead
		}
		want := v.ref.Size()
		part := model.MultipartPart{BytesRead: r.BytesRead, BodyComplete: r.BodyComplete, ExpectedBytes: &want, Comparison: "not_compared"}
		if identity {
			v.compare(&part, body, 0, want, r.BodyComplete)
		}
		r.FullComparison = &part
	case http.StatusPartialContent:
		r.ResponseForm = "single_206"
		ct := header.Get("Content-Type")
		token, _, _ := strings.Cut(ct, ";")
		mediaType, params, err := mime.ParseMediaType(ct)
		if len(header.Values("Content-Type")) > 1 {
			v.add("MULTIPART_CONTENT_TYPE", "206 has repeated Content-Type fields")
		}
		if mediaType == "multipart/byteranges" || strings.EqualFold(strings.TrimSpace(token), "multipart/byteranges") {
			r.ResponseForm = "multipart_206"
			if len(header.Values("Content-Range")) != 0 {
				v.add("MULTIPART_TOP_CONTENT_RANGE", "multipart 206 has a top-level Content-Range field")
			}
			boundary := params["boundary"]
			if err != nil || multipart.NewWriter(io.Discard).SetBoundary(boundary) != nil {
				r.MultipartFraming = "invalid"
				v.add("MULTIPART_CONTENT_TYPE", "multipart Content-Type needs a valid boundary parameter")
			} else if identity {
				v.verifyParts(body, boundary)
			} else {
				r.MultipartFraming = "incomplete"
			}
		} else {
			r.Parts = append(r.Parts, v.verifyPart(header.Values("Content-Range"), body, r.BodyComplete, identity, 0))
		}
		if v.total != nil {
			for _, part := range r.Parts {
				if part.Total == nil && part.Last != nil && *part.Last >= *v.total {
					v.add("MULTIPART_TOTAL_CONFLICT", "part offset extends beyond the complete length reported by another part",
						model.Ev("content_range", part.ContentRange), model.Ev("reported_length", *v.total))
				}
			}
		}
		v.coverage()
	default:
		r.ResponseForm = "other"
		v.add("MULTIPART_UNEXPECTED_STATUS", "status does not establish a two-range result", model.Ev("status", r.Status))
	}
}

func (v *multipartVerifier) verifyPart(values []string, body []byte, complete, identity bool, boundaryLen int) model.MultipartPart {
	part := model.MultipartPart{BytesRead: int64(len(body)), BodyComplete: complete, Comparison: "not_compared"}
	id := "MULTIPART_PART_CONTENT_RANGE"
	if boundaryLen == 0 {
		id = "CONTENT_RANGE_INVALID"
	}
	if len(values) != 1 {
		if boundaryLen == 0 && len(values) == 0 {
			id = "STATUS_206_NO_CONTENT_RANGE"
		}
		v.add(id, "206 payload requires exactly one Content-Range field", model.Ev("field_count", len(values)))
		return part
	}
	part.ContentRange = v.clean(values[0])
	cr, err := rangespec.ParseContentRange(values[0])
	if err != nil || cr.Unsatisfied {
		if err == rangespec.ErrNumberRange {
			id = "NUMBER_OUT_OF_RANGE"
		}
		v.add(id, "206 payload has an unusable Content-Range", model.Ev("content_range", part.ContentRange))
		return part
	}
	part.First, part.Last = &cr.First, &cr.Last
	if cr.TotalKnown {
		part.Total = &cr.Total
		if v.total == nil {
			v.total = part.Total
		} else if *v.total != cr.Total {
			v.add("MULTIPART_TOTAL_CONFLICT", "parts report different complete representation lengths",
				model.Ev("first_total", *v.total), model.Ev("part_total", cr.Total))
		}
	}
	interval := model.ByteInterval{First: cr.First, Last: cr.Last}
	paired, rangeIndex := v.matchInterval(interval)
	if !paired && rangeIndex == -1 {
		v.add("CONTENT_RANGE_OUTSIDE_REQUEST", "Content-Range is outside the requested intervals and cannot be explained by coalescing",
			model.Ev("content_range", part.ContentRange))
	}
	// The inclusive length can overflow only for 0-MaxInt64. Check before
	// computing it, including when the server supplies an unknown total.
	want, ok := rangespec.SatAdd(cr.Last-cr.First, 1)
	if !ok {
		v.add("NUMBER_OUT_OF_RANGE", "Content-Range interval length exceeds int64", model.Ev("content_range", part.ContentRange))
		return part
	}
	part.ExpectedBytes = &want
	if boundaryLen == 0 && v.report.ContentLength != nil && *v.report.ContentLength != want {
		v.add("CONTENT_LENGTH_RANGE_MISMATCH", "HTTP Content-Length differs from the declared interval length",
			model.Ev("content_length", *v.report.ContentLength), model.Ev("interval_length", want))
	}
	switch {
	case part.BytesRead > want:
		v.add("BODY_EXCESS", "payload is longer than its declared range", model.Ev("content_range", part.ContentRange), model.Ev("bytes_read", part.BytesRead))
	case complete && part.BytesRead < want:
		v.add("BODY_TRUNCATED", "payload is shorter than its declared range", model.Ev("content_range", part.ContentRange), model.Ev("bytes_read", part.BytesRead))
	}
	if boundaryLen != 0 && rangeIndex >= 0 {
		v.trackOrder(rangeIndex)
	}
	if identity {
		if cr.Last < v.ref.Size() {
			v.compare(&part, body, cr.First, want, complete)
		}
		if (paired || rangeIndex >= 0) && part.BytesRead > 0 {
			observed := model.ByteInterval{First: cr.First, Last: cr.First + (min(part.BytesRead, want) - 1)}
			v.spans = append(v.spans, observed)
		}
		if paired {
			v.coalescing(interval, boundaryLen, part.Comparison == "match")
		}
	}
	return part
}

// matchInterval recognizes a range wholly inside one request or an interval
// bridging the gap while intersecting both requests.
func (v *multipartVerifier) matchInterval(span model.ByteInterval) (bool, int) {
	r := v.report.Requested
	for i, want := range r {
		if want.First <= span.First && span.Last <= want.Last {
			return false, i
		}
	}
	lo, hi := v.offsetOrder()
	return lo.First <= span.First && span.First <= lo.Last && hi.First <= span.Last && span.Last <= hi.Last, -1
}

func (v *multipartVerifier) offsetOrder() (lo, hi model.ByteInterval) {
	lo, hi = v.report.Requested[0], v.report.Requested[1]
	if lo.First > hi.First {
		return hi, lo
	}
	return lo, hi
}

func (v *multipartVerifier) coalescing(span model.ByteInterval, boundaryLen int, match bool) {
	r := v.report
	lo, hi := v.offsetOrder()
	gap := hi.First - lo.Last - 1
	// The minimum additional MIME part is a delimiter, the shortest
	// possible Content-Range field, and the header terminator. A single
	// part 206 gives no evidence of a counterfactual boundary or media type.
	minimumOverhead := int64(len("\r\n--\r\nContent-Range:bytes 0-0/*\r\n\r\n") + max(boundaryLen, 1))
	if gap >= minimumOverhead {
		if r.Coalescing != "overhead_unverified" {
			v.add("MULTIPART_COALESCING_UNCERTAIN", "response bridges a gap whose coalescing cannot be confirmed from the available MIME overhead",
				model.Ev("gap_bytes", gap), model.Ev("minimum_overhead_bytes", minimumOverhead))
		}
		r.Coalescing = "overhead_unverified"
		return
	}
	if r.Coalescing == "" {
		r.Coalescing = "unverified"
	}
	v.coalescedBytes = v.coalescedBytes || (match && span.First == lo.First && span.Last == hi.Last)
}

func (v *multipartVerifier) trackOrder(index int) {
	if v.seenIndex && v.lastIndex > index && v.report.PartOrder != "out_of_order" {
		v.report.PartOrder = "out_of_order"
		v.add("MULTIPART_ORDER", "parts did not follow request order (RFC 9110 recommends this order)")
	} else if v.seenIndex && v.lastIndex != index && v.report.PartOrder == "" {
		v.report.PartOrder = "request_order"
	}
	v.seenIndex, v.lastIndex = true, index
}

func (v *multipartVerifier) coverage() {
	r := v.report
	if len(v.spans) == 0 {
		return
	}
	slices.SortFunc(v.spans, func(a, b model.ByteInterval) int {
		return cmp.Compare(a.First, b.First)
	})
	all := true
	for i, want := range r.Requested {
		next := want.First
		for _, span := range v.spans {
			first, last := max(next, span.First), min(want.Last, span.Last)
			if first <= last {
				r.CoveredBytes[i] += last - first + 1
				next = last + 1
			}
		}
		all = all && r.CoveredBytes[i] == want.Last-want.First+1
	}
	if all {
		r.Coverage = "complete"
	} else if r.BodyComplete && r.ObservationIssue == "" {
		r.Coverage = "partial"
		v.add("MULTIPART_PARTIAL", "206 did not cover all requested bytes")
	} else {
		r.Coverage = "incomplete_observation"
	}
}

func (v *multipartVerifier) compare(part *model.MultipartPart, body []byte, start, want int64, complete bool) {
	n := min(int64(len(body)), want)
	if n == 0 && want != 0 {
		return
	}
	var refBytes [32 << 10]byte
	for off := int64(0); off < n; {
		if v.stopVerification() {
			break
		}
		size := min(n-off, int64(len(refBytes)))
		read, err := v.ref.ReadAt(refBytes[:size], start+off)
		if int64(read) != size || err != nil {
			v.add("MULTIPART_REFERENCE_READ", "could not read the reference slice", model.Ev("offset", start+off))
			return
		}
		got := body[off : off+size]
		if part.FirstMismatch == nil && !bytes.Equal(got, refBytes[:size]) {
			for i, b := range got {
				if b != refBytes[i] {
					first := start + off + int64(i)
					part.FirstMismatch = &first
					break
				}
			}
		}
		part.BytesCompared += size
		off += size
	}
	switch {
	case part.FirstMismatch != nil:
		part.Comparison = "mismatch"
		v.add("MULTIPART_BYTES_MISMATCH", "observed payload bytes differ from the reference slice",
			model.Ev("first_mismatch", *part.FirstMismatch), model.Ev("bytes_compared", part.BytesCompared))
	case complete && int64(len(body)) == want && part.BytesCompared == want:
		part.Comparison = "match"
	case part.BytesCompared > 0:
		part.Comparison = "prefix_match"
	}
}

func (v *multipartVerifier) finish() {
	r := v.report
	status := model.KindPass
	for _, finding := range r.Findings {
		status = model.Worse(status, finding.Kind)
	}
	switch {
	case status == model.KindViolation || status == model.KindByteMismatch:
		r.Result, r.ExitCode = model.ResultProblem, model.ExitProblem
	case r.ObservationIssue == string(transport.FailCancelled) || (v.verificationStopped && v.ctx.Err() == context.Canceled):
		r.Result, r.ExitCode = model.ResultIncomplete, model.ExitInterrupted
	case status != model.KindPass || r.ObservationIssue != "":
		r.Result, r.ExitCode = model.ResultIncomplete, model.ExitIncomplete
	case r.ResponseForm == "full_200":
		r.Result, r.ExitCode = model.ResultRangeIgnored, model.ExitRangeIgnored
	case r.Coverage == "complete":
		r.Result, r.ExitCode = model.ResultPass, model.ExitPass
		if len(r.Parts) == 1 && v.coalescedBytes {
			r.Coalescing = "confirmed"
		}
	default:
		r.Result, r.ExitCode = model.ResultIncomplete, model.ExitIncomplete
	}
}
