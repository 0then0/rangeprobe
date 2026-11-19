package model

// MultipartReport is the separate report for a single two-range GET.
type MultipartReport struct {
	SchemaVersion    int             `json:"schema_version"`
	Mode             string          `json:"mode"`
	Tool             ToolInfo        `json:"tool"`
	Target           string          `json:"target"`
	Endpoint         EndpointInfo    `json:"endpoint"`
	Reference        ReferenceInfo   `json:"reference"`
	Range            string          `json:"range"`
	Requested        [2]ByteInterval `json:"requested"`
	Status           int             `json:"status,omitempty"`
	ResponseForm     string          `json:"response_form"`
	ContentType      string          `json:"content_type,omitempty"`
	ContentRange     string          `json:"content_range,omitempty"`
	ContentLength    *int64          `json:"content_length,omitempty"`
	BodyLimit        int64           `json:"body_limit"`
	BytesRead        int64           `json:"bytes_read"`
	BodyComplete     bool            `json:"body_complete"`
	ObservationIssue string          `json:"observation_issue,omitempty"`
	MultipartFraming string          `json:"multipart_framing,omitempty"`
	ClosingBoundary  bool            `json:"closing_boundary"`
	PartOrder        string          `json:"part_order,omitempty"`
	Parts            []MultipartPart `json:"parts,omitempty"`
	FullComparison   *MultipartPart  `json:"full_comparison,omitempty"`
	Coverage         string          `json:"coverage"`
	CoveredBytes     [2]int64        `json:"covered_bytes"`
	Coalescing       string          `json:"coalescing,omitempty"`
	Findings         []Finding       `json:"findings"`
	Result           string          `json:"result"`
	ExitCode         int             `json:"exit_code"`
}

// ByteInterval is an inclusive interval of byte offsets.
type ByteInterval struct {
	First int64 `json:"first"`
	Last  int64 `json:"last"`
}

// MultipartPart describes one payload and its comparison at the declared offset.
// A 200 response uses the same comparison fields without a Content-Range.
type MultipartPart struct {
	ContentRange  string `json:"content_range,omitempty"`
	First         *int64 `json:"first,omitempty"`
	Last          *int64 `json:"last,omitempty"`
	Total         *int64 `json:"total,omitempty"`
	ExpectedBytes *int64 `json:"expected_bytes,omitempty"`
	BytesRead     int64  `json:"bytes_read"`
	BodyComplete  bool   `json:"body_complete"`
	BytesCompared int64  `json:"bytes_compared"`
	FirstMismatch *int64 `json:"first_mismatch,omitempty"`
	Comparison    string `json:"comparison"`
}
