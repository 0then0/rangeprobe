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
		if c.Findings == nil {
			c.Findings = []model.Finding{}
		}
		for j := range c.Findings {
			f := &c.Findings[j]
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
