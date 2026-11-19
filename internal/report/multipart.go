package report

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/0then0/rangeprobe/internal/model"
	"github.com/0then0/rangeprobe/internal/redact"
)

// MultipartText renders the evidence from a single two-range GET.
func MultipartText(r *model.MultipartReport) []byte {
	var buf bytes.Buffer
	line := func(format string, args ...any) {
		fmt.Fprintln(&buf, redact.Clean(fmt.Sprintf(format, args...), 0))
	}
	line("RangeProbe %s, multipart mode", r.Tool.Version)
	line("Target:    %s", r.Target)
	if r.Endpoint.FinalURL != "" && (r.Endpoint.FinalURL != r.Target || len(r.Endpoint.Redirects) > 0) {
		line("Endpoint:  %s (%d redirects)", r.Endpoint.FinalURL, len(r.Endpoint.Redirects))
	}
	line("Reference: %s (%s bytes)", r.Reference.Name, commas(r.Reference.Size))
	line("Range:     %s", r.Range)
	line("")
	line("RESULT: %s (exit code %d)", strings.ToUpper(strings.ReplaceAll(r.Result, "_", " ")), r.ExitCode)
	if r.Status != 0 {
		line("  HTTP %d (%s)", r.Status, r.ResponseForm)
	} else {
		line("  No HTTP response")
	}
	if r.ContentType != "" {
		line("  Content-Type: %s", r.ContentType)
	}
	if r.ContentRange != "" {
		line("  Content-Range: %s", r.ContentRange)
	}
	if r.ContentLength != nil {
		line("  Content-Length: %s", commas(*r.ContentLength))
	}
	line("  Body: %s of %s allowed bytes read (complete: %t)", commas(r.BytesRead), commas(r.BodyLimit), r.BodyComplete)
	if r.ObservationIssue != "" {
		line("  Observation issue: %s", r.ObservationIssue)
	}
	if r.MultipartFraming != "" {
		line("  Multipart framing: %s (closing boundary: %t)", r.MultipartFraming, r.ClosingBoundary)
	}
	if r.PartOrder != "" {
		line("  Part order: %s", r.PartOrder)
	}
	line("  Range coverage: %s", r.Coverage)
	for i, interval := range r.Requested {
		line("    %d-%d: %s bytes covered", interval.First, interval.Last, commas(r.CoveredBytes[i]))
	}
	if r.Coalescing != "" {
		line("  Coalescing: %s", r.Coalescing)
	}

	part := func(label string, e model.MultipartPart) {
		line("  %s: %s (%s payload bytes identified, %s compared, complete: %t)", label, e.Comparison, commas(e.BytesRead), commas(e.BytesCompared), e.BodyComplete)
		if e.ContentRange != "" {
			line("    Content-Range: %s", e.ContentRange)
		}
		if e.ExpectedBytes != nil {
			line("    Expected length: %s bytes", commas(*e.ExpectedBytes))
		}
		if e.FirstMismatch != nil {
			line("    First mismatch at offset %d", *e.FirstMismatch)
		}
	}
	for i, e := range r.Parts {
		part(fmt.Sprintf("Part %d", i+1), e)
	}
	if r.FullComparison != nil {
		part("Full response comparison", *r.FullComparison)
	}
	for _, finding := range r.Findings {
		line("  [%s] %s: %s", finding.ID, finding.Kind, finding.Message)
		for _, evidence := range finding.Evidence {
			line("    %s = %s", evidence.Key, evidence.Value)
		}
		for _, limit := range finding.Limits {
			line("    Limit: %s", limit)
		}
	}
	return buf.Bytes()
}
