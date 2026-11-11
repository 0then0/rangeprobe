package probe

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/0then0/rangeprobe/internal/interpret"
	"github.com/0then0/rangeprobe/internal/model"
	"github.com/0then0/rangeprobe/internal/plan"
	"github.com/0then0/rangeprobe/internal/rangespec"
	"github.com/0then0/rangeprobe/internal/transport"
)

type ifRangeProbe struct {
	role, validator string
}

func (p *ifRangeProbe) evidence() *model.IfRangeEvidence {
	return &model.IfRangeEvidence{
		Role: p.role, Validator: interpret.DisplayETag(p.validator),
		ValidatorBase64: base64.StdEncoding.EncodeToString([]byte(p.validator)),
		Condition:       "unknown", Identity: "unavailable", Outcome: "unavailable",
		Reason: "probe was not sent", InvalidClientInput: p.role == "weak",
	}
}

func (r *runner) runIfRange() {
	item := func(role string) plan.Item {
		return plan.Item{ID: "if-range-" + role, Title: "If-Range " + role,
			Key: true, Claim: "Observe conditional range handling; body completeness is a separate claim.",
			Spec:        rangespec.Spec{Kind: rangespec.KindInt, First: 0, Last: r.opt.ProbeSize - 1},
			ExpectBytes: r.opt.ProbeSize, Retain: true}
	}
	r.checks = append(r.checks, r.executeProbe(item("baseline"), &ifRangeProbe{role: "baseline"}))
	var tag interpret.ETag
	if r.baseline != nil {
		tag = r.baseline.ETag
	}
	for _, role := range []string{"matching", "mismatching", "weak"} {
		if role == "weak" && !r.opt.WeakIfRange {
			continue
		}
		it := item(role)
		p := &ifRangeProbe{role: role}
		if (role != "weak" && tag.Kind != interpret.ETagStrong) || (role == "weak" && !tag.Valid()) {
			it.Skip = &model.Skip{ID: "SKIP_IF_RANGE_VALIDATOR", Reason: "baseline has no usable strong ETag for the main checks (or usable entity-tag for the weak probe)"}
		} else {
			switch role {
			case "matching":
				p.validator = tag.Tag
			case "mismatching":
				// Independent random data, never a modification of the baseline tag.
				for p.validator == "" || p.validator == tag.Tag {
					var b [32]byte
					if _, err := rand.Read(b[:]); err != nil {
						it.Skip = &model.Skip{ID: "SKIP_IF_RANGE_VALIDATOR", Reason: "random validator generation failed"}
						break
					}
					p.validator = `"rangeprobe-` + hex.EncodeToString(b[:]) + `"`
				}
			case "weak":
				p.validator = tag.Tag
				if tag.Kind == interpret.ETagStrong {
					p.validator = "W/" + tag.Tag
				}
			}
		}
		r.checks = append(r.checks, r.executeProbe(it, p))
	}
}

func (r *runner) interpretIfRange(chk *model.Check, p *ifRangeProbe, an *interpret.HeadAnalysis, ex *transport.Exchange, fs []model.Finding, st interpret.BodyState, cur *interpret.Retained) []model.Finding {
	e := chk.IfRange
	e.Outcome, e.Reason = "inconclusive", "no usable response was obtained"
	if an == nil || ex.Fail != nil {
		return fs
	}
	tag := an.FP.ETag
	if tag.Valid() {
		e.ResponseETagBase64 = base64.StdEncoding.EncodeToString([]byte(tag.Tag))
	}
	e.ValidatorSent = p.validator != "" && ex.SentIfRange == p.validator
	if p.role == "baseline" {
		r.ifRangeBaselineURL = ex.FinalURL
		e.Condition, e.Identity = "not_applicable", "baseline"
		switch {
		case an.Head.Status == 206 && st.Complete && !hasProblem(fs):
			e.Outcome, e.Reason = "range_supported", "a complete single-range 206 was observed; original-file identity is not proven"
		case an.Head.Status == 200:
			e.Outcome, e.Reason = "range_ignored", "200 is allowed; range support is not established"
		default:
			e.Reason = "baseline does not establish a usable single-range response"
		}
		return fs
	}
	if r.baseline != nil {
		ev, _ := interpret.Compare(*r.baseline, an.FP)
		e.Identity = ev.String()
	}
	resourceChanged := r.ifRangeBaselineURL != ex.FinalURL
	if resourceChanged {
		e.Identity = "different final resource"
		fs = append(fs, model.NewFinding("IF_RANGE_RESOURCE_CHANGED", "final resource URL differs from baseline; entity-tags from different resources do not establish byte identity"))
	}
	switch {
	case !e.ValidatorSent:
		e.Reason = "If-Range did not reach the final request (redirect forwarding policy)"
	case p.role == "weak":
		e.Condition = "false"
		e.Reason = "weak If-Range is deliberately invalid client input; strong comparison must be false"
	case tag.Kind == interpret.ETagStrong && tag.Tag != p.validator:
		e.Condition = "false"
		e.Reason = "sent validator differs from the current response's complete strong ETag"
	case tag.Kind == interpret.ETagStrong && tag.Tag == p.validator:
		e.Condition = "true"
		e.Reason = "sent validator equals the current response's complete strong ETag"
	default:
		e.Reason = "current response has no usable strong ETag; the condition cannot be established"
	}
	if p.role == "weak" {
		fs = append(fs, model.NewFinding("IF_RANGE_WEAK_INPUT", "opt-in conformance probe: clients MUST NOT generate weak If-Range validators"))
	}
	switch an.Head.Status {
	case 206:
		switch e.Condition {
		case "false":
			e.Outcome = "violation"
			fs = append(fs, model.NewFinding("IF_RANGE_FALSE_206", "206 was returned although the If-Range condition is false",
				model.Ev("validator", e.Validator), model.Ev("response_etag", tag.Display()), model.Ev("premise", e.Reason)))
		case "true":
			if p.role == "matching" && an.EncodingOK && !resourceChanged {
				rf, verified := interpret.Relate(interpret.RelReread, r.retained["if-range-baseline"], cur)
				fs = append(fs, rf...)
				chk.Verified = append(chk.Verified, verified...)
			}
			if st.Complete && !hasProblem(fs) && p.role == "matching" {
				e.Outcome = "conditional_range_supported"
			}
		default:
			fs = append(fs, model.NewFinding("IF_RANGE_PREMISE_UNKNOWN", e.Reason))
		}
	case 200:
		// A fallback is expected when false, not a failure of random access.
		if e.Condition == "false" {
			e.Outcome = "fallback_observed"
			filtered := fs[:0]
			for _, f := range fs {
				if f.ID != "RANGE_IGNORED" {
					filtered = append(filtered, f)
				}
			}
			fs = append(filtered, model.NewFinding("IF_RANGE_FALLBACK", "200 fallback observed; body completeness and correctness are separate",
				model.Ev("bytes_read", ex.Read), model.Ev("body_complete", st.Complete), model.Ev("body_end", st.End)))
		} else if e.Condition == "true" {
			e.Outcome = "range_ignored"
			e.Reason += "; 200 is allowed and does not establish conditional range support"
		} else {
			fs = append(fs, model.NewFinding("IF_RANGE_PREMISE_UNKNOWN", e.Reason))
		}
	default:
		e.Reason = fmt.Sprintf("status %d does not establish fallback or conditional range support", an.Head.Status)
	}
	if p.role == "mismatching" && e.Condition == "true" {
		fs = append(fs, model.NewFinding("IF_RANGE_PREMISE_UNKNOWN", "generated validator unexpectedly matches the current response; mismatch premise is not established"))
	}
	chk.Limits = append(chk.Limits, "A fallback status proves only observed handling of this request. An unread body tail and identity with an original file are not verified.")
	return fs
}

func summarizeIfRange(rep *model.Report) {
	s := &model.IfRangeSummary{ConditionalRanges: "unavailable", MismatchFallback: "unavailable"}
	for _, c := range rep.Checks {
		if c.IfRange == nil {
			continue
		}
		switch c.IfRange.Role {
		case "matching":
			s.ConditionalRanges = c.IfRange.Outcome
		case "mismatching":
			s.MismatchFallback = c.IfRange.Outcome
		}
	}
	rep.IfRange = s
	// For this new mode, an ignored baseline cannot mask a missing validator
	// or transport failure in the main conditional checks. Legacy modes retain
	// their existing precedence.
	if rep.Summary.ExitCode != model.ExitProblem {
		for _, c := range rep.Checks {
			if c.Status == model.KindInconclusive || c.Status == model.KindTransportError || (c.Key && c.Skip != nil) {
				rep.Summary.Result, rep.Summary.ExitCode = model.ResultIncomplete, model.ExitIncomplete
			}
		}
	}
	if rep.Summary.ExitCode == model.ExitPass && (s.ConditionalRanges != "conditional_range_supported" || s.MismatchFallback != "fallback_observed") {
		rep.Summary.Result, rep.Summary.ExitCode = model.ResultIncomplete, model.ExitIncomplete
	}
	rep.Summary.Headline = fmt.Sprintf("Conditional ranges: %s. Mismatch fallback: %s. Body evidence is reported separately.", s.ConditionalRanges, s.MismatchFallback)
}
