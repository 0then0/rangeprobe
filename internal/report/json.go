package report

import (
	"bytes"
	"encoding/json"

	"github.com/0then0/rangeprobe/internal/model"
)

// JSON renders the report as indented JSON with a trailing newline. Slices
// are never null, so consumers can iterate without nil checks.
func JSON(r *model.Report) ([]byte, error) {
	normalize(r)
	return encodeJSON(r)
}

// MultipartJSON renders a two-range report with the same array convention.
func MultipartJSON(r *model.MultipartReport) ([]byte, error) {
	normalizeFindings(&r.Findings)
	return encodeJSON(r)
}

func encodeJSON(r any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(true) // keeps the file safe if it is ever embedded in HTML
	enc.SetIndent("", "  ")
	if err := enc.Encode(r); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func normalize(r *model.Report) {
	for i := range r.Checks {
		c := &r.Checks[i]
		normalizeFindings(&c.Findings)
		if c.Request != nil && c.Request.Headers == nil {
			c.Request.Headers = []model.KV{}
		}
	}
	if r.RunFindings == nil {
		r.RunFindings = []model.Finding{}
	}
	if r.Representation.Changes == nil {
		r.Representation.Changes = []string{}
	}
}

func normalizeFindings(findings *[]model.Finding) {
	if *findings == nil {
		*findings = []model.Finding{}
	}
	for i := range *findings {
		f := &(*findings)[i]
		if f.Evidence == nil {
			f.Evidence = []model.KV{}
		}
		if f.Conditions == nil {
			f.Conditions = []string{}
		}
		if f.Limits == nil {
			f.Limits = []string{}
		}
	}
}
