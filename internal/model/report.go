package model

import (
	"fmt"
	"sort"
	"strings"
)

// Exit codes. They are part of the CLI contract and documented in the README.
const (
	ExitPass         = 0   // every key check passed; nothing confirmed wrong
	ExitProblem      = 1   // confirmed violation or byte mismatch
	ExitRangeIgnored = 2   // Range ignored: no random access; no violation confirmed
	ExitIncomplete   = 3   // no confirmed problem, but checks were inconclusive, skipped or failed
	ExitUsage        = 64  // invalid command line or configuration
	ExitRunError     = 70  // the run could not be performed or its output not written
	ExitInterrupted  = 130 // cancelled by a signal before completion
)

// Result names for Summary.Result.
const (
	ResultPass         = "pass"
	ResultProblem      = "problem"
	ResultRangeIgnored = "range_ignored"
	ResultIncomplete   = "incomplete"
)

// ToolInfo identifies the producer.
type ToolInfo struct {
	Name       string `json:"name"`
	Version    string `json:"version"`
	Repository string `json:"repository"`
}

// Params records the run parameters (no secret values).
type Params struct {
	MaxRequests      int      `json:"max_requests"`
	MaxBytes         int64    `json:"max_total_bytes"`
	MaxBody          int64    `json:"max_response_bytes"`
	RequestTimeoutMS int64    `json:"request_timeout_ms"`
	RunTimeoutMS     int64    `json:"run_timeout_ms"`
	MaxRedirects     int      `json:"max_redirects"`
	ProbeSize        int64    `json:"probe_size"`
	Preconditions    bool     `json:"preconditions"`
	HeaderNames      []string `json:"user_header_names"`
	RedactLocations  bool     `json:"redact_locations"`
	DumpMismatch     int      `json:"dump_mismatch_bytes"`
	CustomCA         bool     `json:"custom_ca"`
}

// RunInfo describes the invocation.
type RunInfo struct {
	Mode        string `json:"mode"`
	StartedAt   string `json:"started_at"`
	FinishedAt  string `json:"finished_at"`
	DurationMS  int64  `json:"duration_ms"`
	Target      string `json:"target"`
	Params      Params `json:"params"`
	Interrupted bool   `json:"interrupted"`
}

// ReferenceInfo describes the local reference file.
type ReferenceInfo struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
}

// EndpointInfo records where the probes ended up.
type EndpointInfo struct {
	FinalURL  string     `json:"final_url,omitempty"`
	Redirects []Redirect `json:"redirects,omitempty"`
	Varied    bool       `json:"varied_between_requests"`
}

// RepresentationInfo summarises what the responses said about the file.
type RepresentationInfo struct {
	Length       *int64   `json:"length"`
	LengthBasis  string   `json:"length_basis,omitempty"`
	ETag         string   `json:"etag,omitempty"`
	ETagStrength string   `json:"etag_strength"`
	LastModified string   `json:"last_modified,omitempty"`
	AcceptRanges string   `json:"accept_ranges,omitempty"`
	ContentType  string   `json:"content_type,omitempty"`
	Stable       bool     `json:"stable"`
	Changes      []string `json:"changes,omitempty"`
}

// Summary is the overall verdict.
type Summary struct {
	Result          string         `json:"result"`
	ExitCode        int            `json:"exit_code"`
	Headline        string         `json:"headline"`
	Counts          map[string]int `json:"counts"`
	MismatchPattern string         `json:"mismatch_pattern,omitempty"`
	NotPassed       []string       `json:"key_checks_not_passed,omitempty"`
	SkippedOptional []string       `json:"optional_checks_skipped,omitempty"`
}

// Uncertainty names a reason a conclusion is limited.
type Uncertainty struct {
	Source string `json:"source"`
	ID     string `json:"id,omitempty"`
	Text   string `json:"text"`
}

// BudgetUsage reports consumption against the limits.
type BudgetUsage struct {
	Requests    int   `json:"requests"`
	MaxRequests int   `json:"max_requests"`
	BytesRead   int64 `json:"bytes_read"`
	MaxBytes    int64 `json:"max_total_bytes"`
}

// Report is the versioned JSON document.
type Report struct {
	SchemaVersion  int                `json:"schema_version"`
	Tool           ToolInfo           `json:"tool"`
	Run            RunInfo            `json:"run"`
	Reference      *ReferenceInfo     `json:"reference,omitempty"`
	Endpoint       EndpointInfo       `json:"endpoint"`
	Representation RepresentationInfo `json:"representation"`
	Summary        Summary            `json:"summary"`
	Checks         []Check            `json:"checks"`
	RunFindings    []Finding          `json:"run_findings"`
	VerifiedClaims []string           `json:"verified_claims"`
	Unsupported    []string           `json:"unsupported"`
	Uncertainty    []Uncertainty      `json:"uncertainty"`
	Assumptions    []string           `json:"assumptions"`
	Budget         BudgetUsage        `json:"budget"`
}

// Summarize derives Summary from the checks and run-level findings.
func (r *Report) Summarize() {
	counts := map[string]int{}
	var problem, ignored, incomplete bool
	var notPassed, skippedOpt []string
	var mism, mismTotal int
	for _, c := range r.Checks {
		counts[string(c.Status)]++
		switch c.Status {
		case KindViolation, KindByteMismatch:
			problem = true
		case KindRangeIgnored:
			ignored = true
		case KindInconclusive, KindTransportError:
			incomplete = true
		case KindSkipped:
			if c.Key {
				incomplete = true
			}
		}
		if c.Status != KindPass && c.Key {
			notPassed = append(notPassed, c.ID)
		}
		if c.Status == KindSkipped && !c.Key {
			skippedOpt = append(skippedOpt, c.ID)
		}
		if c.Body != nil && c.Body.Reference != nil && c.Body.Reference.Compared > 0 {
			mismTotal++
			if !c.Body.Reference.Match && c.Body.Reference.FirstMismatch != nil {
				mism++
			}
		}
	}
	for _, f := range r.RunFindings {
		if f.Kind == KindInconclusive || f.Kind == KindTransportError {
			incomplete = true
		}
	}
	s := Summary{Counts: counts, NotPassed: notPassed, SkippedOptional: skippedOpt}
	switch {
	case problem:
		s.Result, s.ExitCode = ResultProblem, ExitProblem
	case ignored:
		s.Result, s.ExitCode = ResultRangeIgnored, ExitRangeIgnored
	case incomplete || len(notPassed) > 0:
		s.Result, s.ExitCode = ResultIncomplete, ExitIncomplete
	default:
		s.Result, s.ExitCode = ResultPass, ExitPass
	}
	if mism > 0 && r.Reference != nil {
		switch {
		case mism == mismTotal && mismTotal > 1:
			s.MismatchPattern = fmt.Sprintf("every compared response (%d of %d) differs from the reference; the reference may be a different file or version", mism, mismTotal)
		default:
			s.MismatchPattern = fmt.Sprintf("%d of %d compared responses differ from the reference; the others matched, so the difference is range-specific or limited to part of the file", mism, mismTotal)
		}
	}
	s.Headline = headline(s, counts)
	r.Summary = s
}

func headline(s Summary, counts map[string]int) string {
	var parts []string
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%d %s", counts[k], strings.ReplaceAll(k, "_", " ")))
	}
	counted := strings.Join(parts, ", ")
	switch s.Result {
	case ResultPass:
		return "All key checks passed (" + counted + "). Content identity with an unseen original is not proven."
	case ResultProblem:
		return "A confirmed problem was found (" + counted + ")."
	case ResultRangeIgnored:
		return "The server ignored Range; random access is not available here (" + counted + "). This is not an RFC violation."
	}
	return "Verification is incomplete (" + counted + "); no confirmed problem, but not a PASS."
}
