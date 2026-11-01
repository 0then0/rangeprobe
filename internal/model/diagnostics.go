package model

import "sort"

// DiagInfo is the static description of a stable diagnostic ID. Findings add
// concrete evidence at run time.
type DiagInfo struct {
	Kind  Kind
	Title string
	// Conditions are the facts that must hold for the diagnostic to apply.
	Conditions []string
}

// Registry lists every diagnostic and skip-reason ID. IDs are stable across
// patch releases; docs/diagnostics.md documents each one and a test keeps the
// two in sync.
var Registry = map[string]DiagInfo{
	// Confirmed protocol-contract violations.
	"STATUS_206_NO_CONTENT_RANGE": {KindViolation, "206 response has no Content-Range",
		[]string{"status is 206", "Content-Type is not multipart/byteranges", "RFC 9110 15.3.7.1 requires Content-Range in a single-part 206"}},
	"CONTENT_RANGE_INVALID": {KindViolation, "Content-Range is malformed or self-contradictory",
		[]string{"status is 206 (or 416)", "value fails the RFC 9110 14.4 grammar, has last-pos < first-pos, complete-length <= last-pos, a unit other than bytes, or is repeated"}},
	"CONTENT_RANGE_OUTSIDE_REQUEST": {KindViolation, "Content-Range is not within the requested range",
		[]string{"status is 206", "Content-Range is valid", "the interval implied by the request and the response's own complete length does not contain the declared interval"}},
	"CONTENT_LENGTH_RANGE_MISMATCH": {KindViolation, "Content-Length disagrees with the Content-Range interval",
		[]string{"status is 206", "Content-Range is valid", "Content-Length is present and differs from last-pos - first-pos + 1"}},
	"BODY_TRUNCATED": {KindViolation, "body ended before the declared length",
		[]string{"status is 206 (or 200 with Content-Length)", "the peer closed the stream cleanly or the framing ended early before the declared octets arrived", "the read was not cut by a RangeProbe budget"}},
	"BODY_EXCESS": {KindViolation, "body is longer than the declared range",
		[]string{"status is 206", "the stream delivered at least one octet beyond the Content-Range length", "the extra octet fit in the remaining byte budget"}},
	"UNSATISFIABLE_GOT_206": {KindViolation, "206 returned for a range that is unsatisfiable under the reported length",
		[]string{"status is 206 with a valid Content-Range carrying a complete length", "the request's first-pos is at or beyond that length"}},
	"SATISFIABLE_GOT_416": {KindViolation, "416 returned although the range is satisfiable under the length it reports",
		[]string{"status is 416 with Content-Range bytes */length", "the requested range is satisfiable for that length"}},
	"OVERLAP_INCONSISTENT": {KindViolation, "overlapping ranges disagree under one strong ETag",
		[]string{"two complete 206 bodies with overlapping intervals", "both responses carry the same strong ETag and no conflicting length or Last-Modified", "the overlapping octets differ"}},
	"REREAD_INCONSISTENT": {KindViolation, "re-reading the same range returned different bytes under one strong ETag",
		[]string{"two complete 206 bodies for the same interval", "both responses carry the same strong ETag and no conflicting length or Last-Modified", "the octets differ"}},

	// Observed mismatch with the local reference.
	"BYTES_MISMATCH_REFERENCE": {KindByteMismatch, "response bytes differ from the reference slice",
		[]string{"reference mode", "response is 206 (or a 200 prefix), uses identity encoding, and its representation signals do not conflict with earlier responses", "the reference file length equals the length the server reports"}},

	// Range ignored: incompatible with random access, not an RFC violation.
	"RANGE_IGNORED": {KindRangeIgnored, "server ignored the Range header and sent a full 200 response",
		[]string{"a single satisfiable or unsatisfiable range was requested", "status is 200", "RFC 9110 14.2 lets a server ignore Range, so this is not a violation"}},

	// Inconclusive.
	"REFERENCE_SIZE_MISMATCH": {KindInconclusive, "reference length differs from the length the server reports",
		[]string{"reference mode", "the server reported a complete length", "the reference file has a different length"}},
	"REFERENCE_CHANGED": {KindInconclusive, "reference file changed while the run was in progress",
		[]string{"size or modification time of the reference differs between start and end of the run"}},
	"REPRESENTATION_CHANGED": {KindInconclusive, "representation signals changed between responses",
		[]string{"a strong or weak ETag, complete length, Last-Modified or content coding differs from an earlier response"}},
	"ENCODING_UNSUPPORTED": {KindInconclusive, "response carries a content coding other than identity",
		[]string{"Accept-Encoding: identity was requested", "response has Content-Encoding other than identity", "RangeProbe does not compare encoded bytes with a reference"}},
	"MULTIPART_UNSUPPORTED": {KindInconclusive, "multipart/byteranges response to a single-range request",
		[]string{"status is 206", "Content-Type is multipart/byteranges", "multipart parsing is not supported in v0.1"}},
	"NUMBER_OUT_OF_RANGE": {KindInconclusive, "a number in the response exceeds the supported 63-bit range",
		[]string{"the numeral is syntactically valid", "it exceeds 9223372036854775807"}},
	"BODY_LIMIT_REACHED": {KindInconclusive, "reading stopped at a byte limit before the declared length",
		[]string{"the declared body is longer than the per-response limit or remaining byte budget"}},
	"CONSISTENCY_UNATTRIBUTED": {KindInconclusive, "bytes differ but one representation is not established",
		[]string{"two complete bodies for overlapping or identical intervals differ", "no shared strong ETag proves they come from one representation"}},
	"PRECONDITION_FAILED": {KindInconclusive, "If-Match precondition failed (412)",
		[]string{"--preconditions was set", "status is 412"}},
	"UNEXPECTED_416": {KindInconclusive, "416 without a Content-Range for a range that earlier responses suggest is satisfiable",
		[]string{"status is 416 without a usable complete length", "an earlier response reported a length for which the range is satisfiable"}},
	"HTTP_STATUS_UNEXPECTED": {KindInconclusive, "status does not allow a range verdict",
		[]string{"status is not 200, 206 or 416 and is not a server error"}},
	"RELATION_INPUT_UNAVAILABLE": {KindInconclusive, "bodies needed for a consistency comparison are unavailable",
		[]string{"one of the compared responses was not a complete verified 206 body"}},

	// Transport / infrastructure.
	"REQUEST_FAILED": {KindTransportError, "request failed before a response was received",
		[]string{"DNS, connection, TLS or protocol failure"}},
	"REQUEST_TIMEOUT": {KindTransportError, "request timed out",
		[]string{"the per-request or whole-run timeout expired"}},
	"BODY_READ_ERROR": {KindTransportError, "reading the body failed",
		[]string{"a network error other than a clean early end of stream occurred"}},
	"REDIRECT_REFUSED": {KindTransportError, "redirect refused by policy",
		[]string{"redirect target would downgrade HTTPS, use a non-HTTP scheme, or be malformed"}},
	"REDIRECT_LIMIT": {KindTransportError, "too many redirects",
		[]string{"redirect count exceeded --max-redirects"}},
	"HTTP_SERVER_ERROR": {KindTransportError, "server or gateway error",
		[]string{"status is 5xx, 408 or 429"}},
	"CANCELLED": {KindTransportError, "run cancelled",
		[]string{"the process received an interrupt"}},

	// Notes (never change a check's status).
	"RANGE_416_CONTENT_RANGE_MISSING": {KindNote, "416 without Content-Range",
		[]string{"status is 416", "RFC 9110 14.4 says a server SHOULD include Content-Range bytes */length"}},
	"PARTIAL_RESPONSE": {KindNote, "206 covers a subset of the requested range",
		[]string{"declared interval lies strictly inside the requested interval", "RFC 9110 15.3.7 allows sending fewer bytes"}},
	"FULL_RESPONSE_CONTENT_RANGE": {KindNote, "Content-Range on a 200 response",
		[]string{"status is 200", "RFC 9110 14.4 gives Content-Range no meaning for 200"}},
	"EXTRA_BYTE_CHECK_SKIPPED": {KindNote, "excess-byte check not performed",
		[]string{"the remaining byte budget or body limit left no room to read one octet beyond the declared length"}},
	"WEAK_VALIDATORS": {KindNote, "only weak or no strong validators observed",
		[]string{"no strong ETag was seen"}},
	"ENDPOINT_VARIED": {KindNote, "final endpoint differed between requests",
		[]string{"redirects led to different hosts or paths for different probes"}},

	// Skip reasons.
	"SKIP_BUDGET_REQUESTS": {KindSkipped, "request budget exhausted", nil},
	"SKIP_BUDGET_BYTES":    {KindSkipped, "remaining byte budget too small for this check", nil},
	"SKIP_BUDGET_TIME":     {KindSkipped, "whole-run timeout reached", nil},
	"SKIP_BODY_LIMIT":      {KindSkipped, "expected response exceeds the per-response limit", nil},
	"SKIP_SIZE_UNKNOWN":    {KindSkipped, "representation length is unknown", nil},
	"SKIP_REMOTE_SIZE":     {KindSkipped, "the server did not report a representation length", nil},
	"SKIP_TOO_SMALL":       {KindSkipped, "representation or probe size too small for this check", nil},
	"SKIP_ZERO_LENGTH":     {KindSkipped, "representation has zero length", nil},
	"SKIP_OVERFLOW":        {KindSkipped, "offsets would exceed the 63-bit range", nil},
	"SKIP_CANCELLED":       {KindSkipped, "run cancelled before this check", nil},
}

// IDs returns every registered ID in sorted order.
func IDs() []string {
	out := make([]string, 0, len(Registry))
	for id := range Registry {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}
