package model

// IfRangeEvidence records the premise separately from the response and body
// verdicts. Base64 fields preserve protocol octets, including non-UTF-8 obs-text;
// display strings must never be used for comparisons or replay.
type IfRangeEvidence struct {
	Role               string `json:"role"`
	Validator          string `json:"validator,omitempty"`
	ValidatorBase64    string `json:"validator_base64,omitempty"`
	ValidatorSent      bool   `json:"validator_sent"`
	ResponseETagBase64 string `json:"response_etag_base64,omitempty"`
	Condition          string `json:"condition"` // true, false, unknown, not_applicable
	Identity           string `json:"baseline_identity"`
	Outcome            string `json:"outcome"`
	Reason             string `json:"reason"`
	InvalidClientInput bool   `json:"invalid_client_input"`
}

// IfRangeSummary keeps conditional range support apart from fallback. A 200
// fallback alone never establishes support for resuming a download.
type IfRangeSummary struct {
	ConditionalRanges string `json:"conditional_ranges"`
	MismatchFallback  string `json:"mismatch_fallback"`
}
