// Package model defines the data produced by a RangeProbe run: checks,
// findings and the versioned report. It contains no I/O.
package model

import "fmt"

// SchemaVersion is the JSON report format version. It is bumped on any
// incompatible change to field names or meaning.
const SchemaVersion = 1

// Kind classifies a finding and, for checks, the resulting Status.
type Kind string

// Finding kinds. A check's Status is the highest-priority kind among its
// findings; KindNote never changes a status.
const (
	KindPass           Kind = "pass"
	KindRangeIgnored   Kind = "range_ignored"
	KindViolation      Kind = "violation"
	KindByteMismatch   Kind = "byte_mismatch"
	KindInconclusive   Kind = "inconclusive"
	KindTransportError Kind = "transport_error"
	KindSkipped        Kind = "skipped"
	KindNote           Kind = "note"
)

// Status is the outcome of a check. It shares values with Kind.
type Status = Kind

// priority orders statuses from most to least significant for display and for
// deriving a check status from its findings.
func priority(k Kind) int {
	switch k {
	case KindViolation:
		return 7
	case KindByteMismatch:
		return 6
	case KindTransportError:
		return 5
	case KindInconclusive:
		return 4
	case KindRangeIgnored:
		return 3
	case KindSkipped:
		return 2
	case KindPass:
		return 1
	}
	return 0
}

// Worse returns the more significant of two statuses.
func Worse(a, b Kind) Kind {
	if priority(b) > priority(a) {
		return b
	}
	return a
}

// KV is an ordered key/value pair.
type KV struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// Finding is one diagnostic with concrete evidence.
type Finding struct {
	ID         string   `json:"id"`
	Kind       Kind     `json:"kind"`
	Message    string   `json:"message"`
	Conditions []string `json:"conditions"`
	Evidence   []KV     `json:"evidence"`
	// Limits states what the finding does not establish.
	Limits []string `json:"limits"`

	// Identity marks findings that rely on the reference or earlier responses
	// describing the same representation; they are downgraded when that
	// assumption is contradicted.
	Identity bool `json:"-"`
}

// NewFinding builds a finding from the registry. It panics on unknown IDs so
// that typos are caught by tests.
func NewFinding(id, msg string, evidence ...KV) Finding {
	info, ok := Registry[id]
	if !ok {
		panic(fmt.Sprintf("model: unregistered diagnostic %q", id))
	}
	return Finding{ID: id, Kind: info.Kind, Message: msg, Conditions: info.Conditions, Evidence: evidence}
}

// Ev is shorthand for building evidence pairs.
func Ev(key string, v any) KV { return KV{Key: key, Value: fmt.Sprint(v)} }

// WithLimits returns f with limits appended.
func (f Finding) WithLimits(l ...string) Finding {
	f.Limits = append(f.Limits, l...)
	return f
}

// AsIdentity marks the finding as depending on representation identity.
func (f Finding) AsIdentity() Finding {
	f.Identity = true
	return f
}

// Downgrade converts the finding to inconclusive with an explanation.
func (f Finding) Downgrade(reason string) Finding {
	f.Kind = KindInconclusive
	f.Limits = append(f.Limits, reason)
	f.Identity = false
	return f
}

// Skip explains why a check was not sent.
type Skip struct {
	ID     string `json:"id"`
	Reason string `json:"reason"`
}

// Redirect is one followed redirect hop (URLs are already redacted).
type Redirect struct {
	Status int    `json:"status"`
	From   string `json:"from"`
	To     string `json:"to"`
}

// RequestInfo describes what was asked.
type RequestInfo struct {
	Method  string `json:"method"`
	URL     string `json:"url"`
	Range   string `json:"range,omitempty"`
	Headers []KV   `json:"headers"`
	// Description is a redacted, secret-free rendering suitable for bug
	// reports.
	Description string `json:"description"`
}

// ResponseInfo describes what the server returned.
type ResponseInfo struct {
	Status        int        `json:"status"`
	Proto         string     `json:"proto"`
	FinalURL      string     `json:"final_url"`
	Redirects     []Redirect `json:"redirects,omitempty"`
	Headers       []KV       `json:"headers"`
	OtherHeaders  int        `json:"other_header_count"`
	ContentLength *int64     `json:"content_length"`
	Chunked       bool       `json:"chunked"`
}

// ByteComparison is the outcome of comparing the body with a reference slice.
type ByteComparison struct {
	Compared        int64  `json:"compared_bytes"`
	ExpectedFirst   int64  `json:"expected_first"`
	ExpectedLast    int64  `json:"expected_last"`
	Match           bool   `json:"match"`
	FirstMismatch   *int64 `json:"first_mismatch_offset,omitempty"`
	MismatchCount   int64  `json:"mismatch_count,omitempty"`
	BeyondReference int64  `json:"bytes_beyond_reference,omitempty"`
	ShiftHint       string `json:"shift_hint,omitempty"`
	ExpectedSHA256  string `json:"expected_sha256,omitempty"`
	// Fragment is present only with --dump-mismatch.
	Fragment *Fragment `json:"fragment,omitempty"`
}

// Fragment is an opt-in hex dump around the first mismatch.
type Fragment struct {
	Offset   int64  `json:"offset"`
	Expected string `json:"expected_hex"`
	Observed string `json:"observed_hex"`
}

// BodyInfo describes the bytes actually read.
type BodyInfo struct {
	BytesRead int64  `json:"bytes_read"`
	ReadLimit int64  `json:"read_limit"`
	Complete  bool   `json:"complete"`
	EndState  string `json:"end_state"`
	SHA256    string `json:"sha256,omitempty"`
	// Declared is the length the response claims, when known.
	Declared  *int64          `json:"declared_length,omitempty"`
	Reference *ByteComparison `json:"reference_comparison,omitempty"`
}

// Check is one probe: its claim, the exchange, the result.
type Check struct {
	ID       string        `json:"id"`
	Title    string        `json:"title"`
	Key      bool          `json:"key"`
	Claim    string        `json:"claim"`
	Status   Status        `json:"status"`
	Skip     *Skip         `json:"skip,omitempty"`
	Request  *RequestInfo  `json:"request,omitempty"`
	Response *ResponseInfo `json:"response,omitempty"`
	Body     *BodyInfo     `json:"body,omitempty"`
	Findings []Finding     `json:"findings"`
	// Verified lists claims that held; empty unless Status is pass or
	// range_ignored with verified side facts.
	Verified   []string         `json:"verified,omitempty"`
	Limits     []string         `json:"limits,omitempty"`
	IfRange    *IfRangeEvidence `json:"if_range,omitempty"`
	DurationMS int64            `json:"duration_ms"`
}

// Finalize derives Status from the findings and Verified claims.
func (c *Check) Finalize() {
	if c.Skip != nil {
		c.Status = KindSkipped
		return
	}
	st := KindPass
	for _, f := range c.Findings {
		if f.Kind == KindNote {
			continue
		}
		st = Worse(st, f.Kind)
	}
	c.Status = st
	if st != KindPass {
		c.Verified = nil
	}
}
