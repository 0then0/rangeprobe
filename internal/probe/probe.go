// Package probe runs the planned checks sequentially under hard budgets and
// assembles the report. It owns the budget accounting; transport enforces
// per-request limits, interpret judges the responses.
package probe

import (
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/0then0/rangeprobe/internal/capture"
	"github.com/0then0/rangeprobe/internal/interpret"
	"github.com/0then0/rangeprobe/internal/model"
	"github.com/0then0/rangeprobe/internal/plan"
	"github.com/0then0/rangeprobe/internal/redact"
	"github.com/0then0/rangeprobe/internal/reference"
	"github.com/0then0/rangeprobe/internal/transport"
	"github.com/0then0/rangeprobe/internal/version"
)

// Budgets are the hard limits of a run. All must be positive.
type Budgets struct {
	MaxRequests    int
	MaxBytes       int64 // total body bytes over the whole run
	MaxBody        int64 // body bytes of a single response
	RequestTimeout time.Duration
	RunTimeout     time.Duration
	MaxRedirects   int
}

// Options configures a run.
type Options struct {
	URL           string
	Ref           *reference.File // nil selects observe mode
	Headers       http.Header     // user-supplied; values are secrets
	ProbeSize     int64
	Budgets       Budgets
	Preconditions bool
	RootCAs       *x509.CertPool
	Redactor      *redact.Redactor
	DumpMismatch  int
	CustomCA      bool

	// RoundTripper replaces the network (tests).
	RoundTripper http.RoundTripper
}

// ignoredPrefix bounds how much of a full 200 response to a range request is
// read. The status already proves Range was ignored; the prefix is read only
// for a sanity comparison with the reference.
const ignoredPrefix = 64 << 10

// maxRetain bounds the memory kept for consistency comparisons per check.
const maxRetain = 8 << 20

// discardLimit bounds bodies of 416 and error responses.
const discardLimit = 4 << 10

type runner struct {
	opt    Options
	rd     *redact.Redactor
	cl     *transport.Client
	parent context.Context
	ctx    context.Context

	reqs  int
	bytes int64

	remote   interpret.RemoteSize
	baseline *interpret.Fingerprint
	ifMatch  string
	retained map[string]*interpret.Retained

	checks      []model.Check
	changes     []string
	strongETag  bool
	firstResp   *model.ResponseInfo
	endpoints   map[string]bool
	repr        model.RepresentationInfo
	reprSet     bool
	refChanged  bool
	interrupted bool
}

// Run executes the probe plan and returns the finished report.
func Run(parent context.Context, opt Options) *model.Report {
	started := time.Now()
	if opt.Redactor == nil {
		opt.Redactor = redact.New(true)
	}
	for _, vals := range opt.Headers {
		for _, v := range vals {
			opt.Redactor.AddSecret(v)
		}
	}
	opt.Redactor.AddURL(opt.URL)
	ctx, cancel := context.WithTimeout(parent, opt.Budgets.RunTimeout)
	defer cancel()
	r := &runner{
		opt: opt, rd: opt.Redactor, parent: parent, ctx: ctx,
		retained:  map[string]*interpret.Retained{},
		endpoints: map[string]bool{},
		cl: transport.New(transport.Config{
			Headers: opt.Headers, RequestTimeout: opt.Budgets.RequestTimeout,
			MaxRedirects: opt.Budgets.MaxRedirects, RootCAs: opt.RootCAs,
			RoundTripper: opt.RoundTripper, Redactor: opt.Redactor,
		}),
		repr: model.RepresentationInfo{ETagStrength: "none", Stable: true},
	}

	r.checks = append(r.checks, r.execute(plan.FirstByte()))
	sz := plan.Sizing{}
	switch {
	case r.remote.Known:
		sz = plan.Sizing{Length: r.remote.Value, Known: true, Remote: true}
	case opt.Ref != nil:
		sz = plan.Sizing{Length: opt.Ref.Size(), Known: true}
	}
	for _, it := range plan.Build(opt.ProbeSize, sz) {
		r.checks = append(r.checks, r.execute(it))
	}
	r.interrupted = parent.Err() != nil
	if opt.Ref != nil && opt.Ref.Changed() {
		r.refChanged = true
	}
	return r.report(started, time.Now())
}

// admit returns a skip reason when the check must not be sent.
func (r *runner) admit(it plan.Item) *model.Skip {
	b := r.opt.Budgets
	switch {
	case r.parent.Err() != nil:
		return &model.Skip{ID: "SKIP_CANCELLED", Reason: "the run was cancelled before this check"}
	case r.ctx.Err() != nil:
		return &model.Skip{ID: "SKIP_BUDGET_TIME", Reason: fmt.Sprintf("the whole-run timeout of %s was reached", b.RunTimeout)}
	case it.Skip != nil:
		return it.Skip
	case it.NeedsRemoteSize && !r.remote.Known:
		return &model.Skip{ID: "SKIP_REMOTE_SIZE", Reason: "the server reported no representation length, so EOF is not established"}
	case r.reqs >= b.MaxRequests:
		return &model.Skip{ID: "SKIP_BUDGET_REQUESTS", Reason: fmt.Sprintf("the budget of %d requests is used up", b.MaxRequests)}
	case it.ExpectBytes > b.MaxBody:
		return &model.Skip{ID: "SKIP_BODY_LIMIT", Reason: fmt.Sprintf("a conforming response (%d bytes) exceeds the per-response limit of %d bytes", it.ExpectBytes, b.MaxBody)}
	case it.ExpectBytes > b.MaxBytes-r.bytes:
		return &model.Skip{ID: "SKIP_BUDGET_BYTES", Reason: fmt.Sprintf("%d bytes are needed but only %d of the %d-byte budget remain", it.ExpectBytes, b.MaxBytes-r.bytes, b.MaxBytes)}
	}
	return nil
}

// capSink forwards at most max bytes so that the one-octet excess probe
// is never compared with the reference.
type capSink struct {
	w   io.Writer
	max int64
	n   int64
}

func (c *capSink) Write(p []byte) (int, error) {
	if room := c.max - c.n; room > 0 {
		c.w.Write(p[:min(int64(len(p)), room)])
	}
	c.n += int64(len(p))
	return len(p), nil
}

func (r *runner) execute(it plan.Item) model.Check {
	chk := model.Check{ID: it.ID, Title: it.Title, Key: it.Key, Claim: it.Claim}
	if sk := r.admit(it); sk != nil {
		chk.Skip = sk
		chk.Finalize()
		return chk
	}
	r.reqs++
	req := transport.Request{URL: r.opt.URL, Range: it.Spec.Header()}
	if r.opt.Preconditions {
		req.IfMatch = r.ifMatch
	}
	params := interpret.Params{Spec: it.Spec, Remote: r.remote, Baseline: r.baseline, IfMatch: req.IfMatch != ""}
	if r.opt.Ref != nil {
		size := r.opt.Ref.Size()
		params.RefSize = &size
	}

	var an *interpret.HeadAnalysis
	var sink *capture.Sink
	ex := r.cl.Fetch(r.ctx, req, func(h *transport.Head) transport.BodyPlan {
		an = interpret.AnalyzeHead(params, h)
		var w io.Writer
		var limit int64
		remaining := r.opt.Budgets.MaxBytes - r.bytes
		maxBody := r.opt.Budgets.MaxBody
		var ref capture.Reference
		if r.opt.Ref != nil && an.EncodingOK {
			ref = r.opt.Ref
		}
		switch an.Mode {
		case interpret.BodyNone:
			return transport.BodyPlan{}
		case interpret.BodyDiscard:
			limit = min(discardLimit, maxBody, remaining)
			sink = capture.New(capture.Config{})
			w = sink
		case interpret.BodyFull:
			limit = min(ignoredPrefix, maxBody, remaining)
			sink = capture.New(capture.Config{Ref: ref})
			w = sink
		case interpret.BodyPartial:
			L := an.Declared()
			limit = min(L+1, maxBody, remaining) // +1 probes for excess bytes
			sink = capture.New(capture.Config{
				Start: an.First, Ref: ref,
				Retain: it.Retain && L <= min(maxBody, maxRetain), RetainMax: int(min(L, maxBody, maxRetain)),
				Dump: r.opt.DumpMismatch,
			})
			w = &capSink{w: sink, max: L}
		}
		return transport.BodyPlan{Limit: limit, Sink: w}
	})
	r.bytes += ex.Read
	chk.DurationMS = ex.Duration.Milliseconds()
	chk.Request = r.requestInfo(req, it)

	var fs []model.Finding
	var st interpret.BodyState
	if ex.Fail != nil || an == nil {
		if ex.Fail != nil {
			fs = append(fs, interpret.FailureFinding(ex.Fail))
		}
		chk.Response = r.hopsOnly(ex)
	} else {
		fs, st = an.Finish(ex, sink, r.opt.Ref != nil)
		fs = interpret.ApplyStability(fs, r.baseline, an.FP)
		chk.Response = r.responseInfo(ex)
		chk.Body = r.bodyInfo(an, ex, st, sink)
		r.observe(it, an, ex, chk.Response)
	}

	var cur *interpret.Retained
	if it.Retain && an != nil && ex.Fail == nil && st.Complete && an.Mode == interpret.BodyPartial &&
		sink != nil && int64(len(sink.Bytes())) == an.Declared() {
		cur = &interpret.Retained{First: an.First, Last: an.Last, Body: sink.Bytes(), FP: an.FP}
		r.retained[it.ID] = cur
	}
	if it.Relation != "" && an != nil && ex.Fail == nil && an.Mode == interpret.BodyPartial {
		other := r.retained[it.With]
		if (cur != nil && other != nil) || !hasProblem(fs) {
			rf, ver := interpret.Relate(interpret.RelationKind(it.Relation), other, cur)
			fs = append(fs, rf...)
			chk.Verified = append(chk.Verified, ver...)
		}
	}

	chk.Findings = fs
	if an != nil && ex.Fail == nil {
		chk.Verified = append(an.Verified(r.opt.Ref != nil, sink), chk.Verified...)
	}
	if r.opt.Ref == nil {
		chk.Limits = append(chk.Limits, "Observe mode: consistency of headers, lengths and repeated reads is checked; identity with the original file is not.")
	} else {
		chk.Limits = append(chk.Limits, "Assumes the reference file is byte-identical to the currently published representation.")
	}
	chk.Finalize()
	if chk.Status == model.KindPass && len(chk.Verified) == 0 {
		chk.Verified = []string{"no inconsistency found for this request"}
	}
	return chk
}

func hasProblem(fs []model.Finding) bool {
	for _, f := range fs {
		if f.Kind != model.KindNote {
			return true
		}
	}
	return false
}

// observe updates run state from a response.
func (r *runner) observe(it plan.Item, an *interpret.HeadAnalysis, ex *transport.Exchange, resp *model.ResponseInfo) {
	st := an.Head.Status
	if st != 200 && st != 206 && st != 416 {
		return
	}
	fp := an.FP
	if r.baseline != nil {
		if ev, why := interpret.Compare(*r.baseline, fp); ev == interpret.EvidenceConflict {
			r.changes = append(r.changes, fmt.Sprintf("%s: %s", it.ID, strings.Join(why, "; ")))
			r.repr.Stable = false
		}
	}
	if r.baseline == nil && (fp.HasETag || fp.TotalKnown || fp.LastModified != "") {
		cp := fp
		r.baseline = &cp
	}
	if fp.HasETag && !fp.ETagWeak {
		r.strongETag = true
		if r.ifMatch == "" {
			r.ifMatch = fp.ETag
		}
	}
	if !r.remote.Known && fp.TotalKnown {
		basis := "content-range"
		if st == 200 {
			basis = "content-length-200"
		}
		r.remote = interpret.RemoteSize{Known: true, Value: fp.Total, Basis: basis}
	}
	if !r.reprSet {
		r.reprSet = true
		r.repr.ETag = fp.ETag
		switch {
		case fp.HasETag && !fp.ETagWeak:
			r.repr.ETagStrength = "strong"
		case fp.HasETag:
			r.repr.ETagStrength = "weak"
		}
		r.repr.LastModified = fp.LastModified
		for _, h := range resp.Headers {
			switch h.Key {
			case "Accept-Ranges":
				r.repr.AcceptRanges = h.Value
			case "Content-Type":
				r.repr.ContentType = h.Value
			}
		}
	}
	if r.firstResp == nil {
		r.firstResp = resp
	}
	if u, err := url.Parse(ex.FinalURL); err == nil {
		r.endpoints[u.Scheme+"://"+u.Host+u.Path] = true
	}
}

var shownResponseHeaders = []string{
	"Accept-Ranges", "Content-Range", "Content-Length", "Content-Type", "Content-Encoding",
	"Transfer-Encoding", "ETag", "Last-Modified", "Date", "Server", "Age", "Via",
	"Cache-Control", "Vary", "Retry-After", "Location",
}

func (r *runner) hopsOnly(ex *transport.Exchange) *model.ResponseInfo {
	if len(ex.Hops) == 0 {
		return nil
	}
	return &model.ResponseInfo{Redirects: r.redirects(ex), Headers: []model.KV{}}
}

func (r *runner) redirects(ex *transport.Exchange) []model.Redirect {
	var out []model.Redirect
	for _, h := range ex.Hops {
		out = append(out, model.Redirect{Status: h.Status, From: r.rd.URL(h.From), To: r.rd.URL(h.To)})
	}
	return out
}

func (r *runner) responseInfo(ex *transport.Exchange) *model.ResponseInfo {
	h := ex.Head
	ri := &model.ResponseInfo{
		Status: h.Status, Proto: redact.Clean(h.Proto, 16), FinalURL: r.rd.URL(ex.FinalURL),
		Redirects: r.redirects(ex), Chunked: h.Chunked, Headers: []model.KV{},
	}
	if h.ContentLength >= 0 {
		v := h.ContentLength
		ri.ContentLength = &v
	}
	shown := map[string]bool{}
	for _, name := range shownResponseHeaders {
		for _, v := range h.Header.Values(name) {
			if name == "Location" {
				v = r.rd.URL(v)
			} else {
				v = redact.Clean(v, 200)
			}
			ri.Headers = append(ri.Headers, model.KV{Key: name, Value: v})
			shown[name] = true
		}
	}
	for name := range h.Header {
		if !shown[name] {
			ri.OtherHeaders++
		}
	}
	return ri
}

func (r *runner) requestInfo(req transport.Request, it plan.Item) *model.RequestInfo {
	u := r.rd.URL(req.URL)
	hs := []model.KV{
		{Key: "Range", Value: req.Range},
		{Key: "Accept-Encoding", Value: "identity"},
		{Key: "User-Agent", Value: version.UserAgent()},
	}
	if req.IfMatch != "" {
		hs = append(hs, model.KV{Key: "If-Match", Value: redact.Clean(req.IfMatch, 200)})
	}
	names := make([]string, 0, len(r.opt.Headers))
	for n := range r.opt.Headers {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		hs = append(hs, model.KV{Key: redact.Clean(n, 80), Value: redact.Placeholder})
	}
	var b strings.Builder
	fmt.Fprintf(&b, "GET %s\n", u)
	for _, h := range hs {
		fmt.Fprintf(&b, "%s: %s\n", h.Key, h.Value)
	}
	return &model.RequestInfo{Method: "GET", URL: u, Range: req.Range, Headers: hs, Description: strings.TrimRight(b.String(), "\n")}
}

func (r *runner) bodyInfo(an *interpret.HeadAnalysis, ex *transport.Exchange, st interpret.BodyState, sink *capture.Sink) *model.BodyInfo {
	bi := &model.BodyInfo{BytesRead: ex.Read, ReadLimit: ex.Limit, Complete: st.Complete, EndState: st.End}
	if sink != nil && sink.N() > 0 {
		bi.SHA256 = sink.SHA256()
	}
	if an.Want >= 0 {
		v := an.Want
		bi.Declared = &v
	}
	if sink != nil && sink.Comparing() && an.EncodingOK && (an.Mode == interpret.BodyPartial || an.Mode == interpret.BodyFull) {
		res := sink.Result()
		first, last := int64(0), res.Compared+res.BeyondReference-1
		if an.Mode == interpret.BodyPartial {
			first, last = an.First, an.Last
		}
		cmp := &model.ByteComparison{
			Compared: res.Compared, ExpectedFirst: first, ExpectedLast: last,
			Match:         res.MismatchCount == 0 && res.RefErr == nil && st.Complete,
			MismatchCount: res.MismatchCount, BeyondReference: res.BeyondReference,
			ShiftHint: res.ShiftHint, ExpectedSHA256: sink.ExpectedSHA256(),
		}
		if res.FirstMismatch >= 0 {
			v := res.FirstMismatch
			cmp.FirstMismatch = &v
		}
		if res.Fragment != nil {
			cmp.Fragment = &model.Fragment{Offset: res.Fragment.Offset, Expected: res.Fragment.Expected, Observed: res.Fragment.Observed}
		}
		bi.Reference = cmp
	}
	return bi
}

func (r *runner) report(started, finished time.Time) *model.Report {
	o := r.opt
	rep := &model.Report{
		SchemaVersion: model.SchemaVersion,
		Tool:          model.ToolInfo{Name: "rangeprobe", Version: version.Version, Repository: version.Repository},
		Run: model.RunInfo{
			Mode: "observe", StartedAt: started.UTC().Format(time.RFC3339), FinishedAt: finished.UTC().Format(time.RFC3339),
			DurationMS: finished.Sub(started).Milliseconds(), Target: r.rd.URL(o.URL), Interrupted: r.interrupted,
			Params: model.Params{
				MaxRequests: o.Budgets.MaxRequests, MaxBytes: o.Budgets.MaxBytes, MaxBody: o.Budgets.MaxBody,
				RequestTimeoutMS: o.Budgets.RequestTimeout.Milliseconds(), RunTimeoutMS: o.Budgets.RunTimeout.Milliseconds(),
				MaxRedirects: o.Budgets.MaxRedirects, ProbeSize: o.ProbeSize, Preconditions: o.Preconditions,
				RedactLocations: o.Redactor.Locations, DumpMismatch: o.DumpMismatch, CustomCA: o.CustomCA,
				HeaderNames: headerNames(o.Headers),
			},
		},
		Checks:      r.checks,
		RunFindings: []model.Finding{},
		Budget:      model.BudgetUsage{Requests: r.reqs, MaxRequests: o.Budgets.MaxRequests, BytesRead: r.bytes, MaxBytes: o.Budgets.MaxBytes},
	}
	if o.Ref != nil {
		rep.Run.Mode = "reference"
		rep.Reference = &model.ReferenceInfo{Name: r.rd.Path(o.Ref.Path()), Size: o.Ref.Size()}
	}
	if r.firstResp != nil {
		rep.Endpoint.FinalURL, rep.Endpoint.Redirects = r.firstResp.FinalURL, r.firstResp.Redirects
	}
	if len(r.endpoints) > 1 {
		rep.Endpoint.Varied = true
		rep.RunFindings = append(rep.RunFindings, model.NewFinding("ENDPOINT_VARIED", "redirects led to different endpoints for different probes",
			model.Ev("distinct_endpoints", len(r.endpoints))))
	}
	rep.Representation = r.repr
	if r.remote.Known {
		v := r.remote.Value
		rep.Representation.Length, rep.Representation.LengthBasis = &v, r.remote.Basis
	}
	rep.Representation.Changes = r.changes
	if !r.strongETag && r.reprSet {
		rep.RunFindings = append(rep.RunFindings, model.NewFinding("WEAK_VALIDATORS", "no strong ETag was seen; identity of the representation across requests cannot be established",
			model.Ev("etag_strength", r.repr.ETagStrength)).
			WithLimits("Consistency findings that need one representation are reported as inconclusive when bytes differ."))
	}
	if r.refChanged {
		rep.RunFindings = append(rep.RunFindings, model.NewFinding("REFERENCE_CHANGED", "the reference file's size or modification time changed during the run"))
		for i := range rep.Checks {
			c := &rep.Checks[i]
			for j, f := range c.Findings {
				if f.Kind == model.KindByteMismatch {
					c.Findings[j] = f.Downgrade("The reference file changed during the run.")
				}
			}
			c.Finalize()
		}
	}
	r.collect(rep)
	rep.Summarize()
	return rep
}

func headerNames(h http.Header) []string {
	out := []string{}
	for n := range h {
		out = append(out, redact.Clean(n, 80))
	}
	sort.Strings(out)
	return out
}

// collect fills the verified/unsupported/uncertainty/assumption sections.
func (r *runner) collect(rep *model.Report) {
	rep.VerifiedClaims = []string{}
	rep.Uncertainty = []model.Uncertainty{}
	unsupported := map[string]bool{}
	for _, c := range rep.Checks {
		for _, v := range c.Verified {
			rep.VerifiedClaims = append(rep.VerifiedClaims, c.ID+": "+v)
		}
		if c.Skip != nil {
			rep.Uncertainty = append(rep.Uncertainty, model.Uncertainty{Source: c.ID, ID: c.Skip.ID, Text: "not run: " + c.Skip.Reason})
		}
		for _, f := range c.Findings {
			switch f.Kind {
			case model.KindInconclusive, model.KindTransportError:
				rep.Uncertainty = append(rep.Uncertainty, model.Uncertainty{Source: c.ID, ID: f.ID, Text: f.Message})
			}
			switch f.ID {
			case "ENCODING_UNSUPPORTED", "MULTIPART_UNSUPPORTED", "NUMBER_OUT_OF_RANGE":
				unsupported[f.ID] = true
			}
		}
	}
	for _, f := range rep.RunFindings {
		if f.Kind == model.KindInconclusive {
			rep.Uncertainty = append(rep.Uncertainty, model.Uncertainty{Source: "run", ID: f.ID, Text: f.Message})
		}
	}
	rep.Unsupported = []string{
		"multipart/byteranges responses (multi-range requests) are not requested or parsed",
		"content codings other than identity: encoded bytes are not compared",
		"If-Range conformance and controlled version switching",
	}
	for _, id := range []string{"ENCODING_UNSUPPORTED", "MULTIPART_UNSUPPORTED", "NUMBER_OUT_OF_RANGE"} {
		if unsupported[id] {
			rep.Unsupported = append(rep.Unsupported, "observed in this run: "+model.Registry[id].Title)
		}
	}
	rep.Assumptions = []string{
		"Requests are sent sequentially and never retried; each probe is independent.",
		"Only body bytes count toward the byte budget; headers do not.",
		"Content-Range offsets and lengths are interpreted as octets of the representation data (RFC 9110 14.1.2), not of any decoded content.",
	}
	if rep.Reference != nil {
		rep.Assumptions = append(rep.Assumptions,
			"The reference file is assumed to be byte-identical to the currently published representation; RangeProbe cannot verify this.",
			"The reference length places offsets when the server reports none; it is not evidence of the remote length.",
			"A byte mismatch is an observation. It does not prove a defect in the server's Range handling: the reference may be another file or version.")
	} else {
		rep.Assumptions = append(rep.Assumptions,
			"No reference was given: results show internal consistency of the server's answers, not identity with any original file.")
	}
}
