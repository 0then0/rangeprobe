package report

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/0then0/rangeprobe/internal/model"
	"github.com/0then0/rangeprobe/internal/redact"
)

// Text writes the human-readable summary. Every line is passed through
// redact.Clean as a last guard, so terminal escape sequences or bidi
// controls from a hostile server cannot reach the user's terminal.
func Text(w io.Writer, r *model.Report) {
	var buf bytes.Buffer
	text(&buf, r)
	for _, line := range strings.Split(strings.TrimRight(buf.String(), "\n"), "\n") {
		fmt.Fprintln(w, redact.Clean(line, 0))
	}
}

func text(w io.Writer, r *model.Report) {
	p := func(format string, a ...any) { fmt.Fprintf(w, format+"\n", a...) }
	p("RangeProbe %s, %s mode", r.Tool.Version, r.Run.Mode)
	p("Target:     %s", r.Run.Target)
	if r.Endpoint.FinalURL != "" && r.Endpoint.FinalURL != r.Run.Target {
		p("Endpoint:   %s (%d redirect(s))", r.Endpoint.FinalURL, len(r.Endpoint.Redirects))
	}
	if r.Reference != nil {
		p("Reference: %s, %s bytes (assumed identical to the published file; not verified)", r.Reference.Name, commas(r.Reference.Size))
	}
	if l := r.Representation.Length; l != nil {
		p("Length:     %s bytes (reported by the server: %s)", commas(*l), r.Representation.LengthBasis)
	} else {
		p("Length:     not reported by the server")
	}
	p("ETag:       %s", etagLine(r))
	p("")
	p("RESULT: %s (exit code %d)", strings.ToUpper(strings.ReplaceAll(r.Summary.Result, "_", " ")), r.Summary.ExitCode)
	p("  %s", r.Summary.Headline)
	if r.Summary.MismatchPattern != "" {
		p("  Pattern: %s", r.Summary.MismatchPattern)
	}
	if len(r.Summary.NotPassed) > 0 {
		p("  Key checks not passed: %s", strings.Join(r.Summary.NotPassed, ", "))
	}
	if r.Run.Interrupted {
		p("  The run was interrupted; remaining checks were skipped.")
	}
	p("")
	p("Checks")
	tw := tabwriter.NewWriter(w, 2, 0, 2, ' ', 0)
	for _, c := range r.Checks {
		resp, read := "-", "-"
		reqRange := "-"
		if c.Request != nil {
			reqRange = c.Request.Range
		}
		switch {
		case c.Skip != nil:
			resp = "skipped: " + c.Skip.ID
		case c.Response != nil && c.Response.Status != 0:
			resp = responseLine(c.Response)
		default:
			resp = "no response"
		}
		if c.Body != nil {
			read = fmt.Sprintf("%s B read (%s)", commas(c.Body.BytesRead), c.Body.EndState)
		}
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\n", c.ID, strings.ToUpper(string(c.Status)), reqRange, resp, read)
	}
	tw.Flush()

	var any bool
	for _, c := range r.Checks {
		for _, f := range c.Findings {
			if f.Kind == model.KindNote && c.Status == model.KindPass && f.ID == "PARTIAL_RESPONSE" {
				continue
			}
			if !any {
				p("")
				p("Findings")
				any = true
			}
			p("  [%s] %s (%s): %s", f.ID, c.ID, strings.ReplaceAll(string(f.Kind), "_", " "), f.Message)
			for _, e := range f.Evidence {
				p("      %s = %s", e.Key, e.Value)
			}
			if len(f.Conditions) > 0 {
				p("      requires: %s", strings.Join(f.Conditions, "; "))
			}
			for _, l := range f.Limits {
				p("      limit: %s", l)
			}
		}
		if c.Skip != nil {
			if !any {
				p("")
				p("Findings")
				any = true
			}
			p("  [%s] %s (skipped): %s", c.Skip.ID, c.ID, c.Skip.Reason)
		}
	}
	for _, f := range r.RunFindings {
		if !any {
			p("")
			p("Findings")
			any = true
		}
		p("  [%s] run (%s): %s", f.ID, strings.ReplaceAll(string(f.Kind), "_", " "), f.Message)
	}
	section(w, "Verified claims", r.VerifiedClaims)
	section(w, "Not supported in v0.1", r.Unsupported)
	var unc []string
	for _, u := range r.Uncertainty {
		unc = append(unc, fmt.Sprintf("%s: %s", u.Source, u.Text))
	}
	section(w, "Reasons for uncertainty", unc)
	section(w, "Assumptions", r.Assumptions)
	p("")
	p("Budget: %d of %d requests, %s of %s body bytes, %d ms",
		r.Budget.Requests, r.Budget.MaxRequests, commas(r.Budget.BytesRead), commas(r.Budget.MaxBytes), r.Run.DurationMS)
}

func section(w io.Writer, title string, items []string) {
	if len(items) == 0 {
		return
	}
	fmt.Fprintf(w, "\n%s\n", title)
	for _, s := range items {
		fmt.Fprintf(w, "  - %s\n", s)
	}
}

func responseLine(r *model.ResponseInfo) string {
	s := fmt.Sprintf("%d", r.Status)
	for _, h := range r.Headers {
		if h.Key == "Content-Range" {
			s += " " + h.Value
		}
	}
	return s
}

func etagLine(r *model.Report) string {
	if r.Representation.ETag == "" {
		return "none seen"
	}
	return fmt.Sprintf("%s (%s)", r.Representation.ETag, r.Representation.ETagStrength)
}

func commas(n int64) string {
	s := fmt.Sprint(n)
	neg := strings.HasPrefix(s, "-")
	s = strings.TrimPrefix(s, "-")
	var out []byte
	for i := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			out = append(out, ',')
		}
		out = append(out, s[i])
	}
	if neg {
		return "-" + string(out)
	}
	return string(out)
}
