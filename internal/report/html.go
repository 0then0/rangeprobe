package report

import (
	"bytes"
	"html/template"
	"strings"

	"github.com/0then0/rangeprobe/internal/model"
)

// HTML renders a self-contained page: inline CSS, no scripts, no external
// resources and no links. Every value is inserted by html/template as text,
// so untrusted headers, URLs and messages cannot inject markup. URLs are
// shown as plain text on purpose.
func HTML(r *model.Report) ([]byte, error) {
	normalize(r)
	var buf bytes.Buffer
	if err := pageTmpl.Execute(&buf, r); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

var pageTmpl = template.Must(template.New("page").Funcs(template.FuncMap{
	"label": func(s any) string {
		var v string
		switch x := s.(type) {
		case string:
			v = x
		case model.Kind:
			v = string(x)
		}
		return strings.ToUpper(strings.ReplaceAll(v, "_", " "))
	},
	"class": func(k model.Kind) string {
		switch k {
		case model.KindPass:
			return "pass"
		case model.KindViolation, model.KindByteMismatch:
			return "bad"
		case model.KindRangeIgnored:
			return "ign"
		case model.KindSkipped, model.KindNote:
			return "mute"
		}
		return "warn"
	},
	"resultClass": func(s string) string {
		switch s {
		case model.ResultPass:
			return "pass"
		case model.ResultProblem:
			return "bad"
		case model.ResultRangeIgnored:
			return "ign"
		}
		return "warn"
	},
	"open": func(k model.Kind) bool { return k != model.KindPass },
	"deref": func(p *int64) any {
		if p == nil {
			return "not reported"
		}
		return *p
	},
	"join":     strings.Join,
	"redacted": func(r *model.Report) bool { return r.Run.Params.RedactLocations },
}).Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<meta name="referrer" content="no-referrer">
<title>RangeProbe report</title>
<style>
:root{color-scheme:light dark;--bg:#fbfbfa;--fg:#1b1f23;--mute:#5d6671;--line:#d8dce1;--card:#fff;--pass:#1a7f37;--bad:#b42318;--warn:#9a6700;--ign:#5b3fa0;--code:#f0f2f4}
@media (prefers-color-scheme:dark){:root{--bg:#14171a;--fg:#e6e8ea;--mute:#9aa4af;--line:#2d343b;--card:#1b2024;--pass:#4cc26a;--bad:#ff7b72;--warn:#e3b341;--ign:#b6a0ff;--code:#252b31}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:56rem;margin:0 auto;padding:1.5rem 1rem 3rem}
h1{font-size:1.4rem;margin:0 0 .25rem}h2{font-size:1.05rem;margin:2rem 0 .6rem}
p,li{overflow-wrap:anywhere}
code,pre,.mono{font:13px/1.45 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
code{background:var(--code);padding:.05rem .3rem;border-radius:3px}
pre{background:var(--code);padding:.6rem .8rem;border-radius:6px;overflow-x:auto;margin:.4rem 0;white-space:pre-wrap;overflow-wrap:anywhere}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:.9rem 1rem;margin:.6rem 0}
.sub{color:var(--mute)}
.badge{display:inline-block;font-weight:600;font-size:.78rem;letter-spacing:.03em;padding:.1rem .5rem;border-radius:999px;border:1px solid currentColor}
.pass{color:var(--pass)}.bad{color:var(--bad)}.warn{color:var(--warn)}.ign{color:var(--ign)}.mute{color:var(--mute)}
dl{display:grid;grid-template-columns:max-content 1fr;gap:.2rem 1rem;margin:.4rem 0}dt{color:var(--mute)}dd{margin:0;overflow-wrap:anywhere}
details{border:1px solid var(--line);border-radius:8px;background:var(--card);margin:.5rem 0}
summary{cursor:pointer;padding:.6rem .9rem;display:flex;gap:.6rem;flex-wrap:wrap;align-items:baseline}
details>div{padding:0 .9rem .8rem}
.finding{border-left:3px solid currentColor;padding:.1rem .7rem;margin:.6rem 0}
.finding h4{margin:0;font-size:.95rem}
ul{margin:.3rem 0;padding-left:1.2rem}
.warnbox{border:1px solid var(--warn);color:var(--warn);border-radius:8px;padding:.5rem .8rem;margin:.6rem 0}
footer{margin-top:2.5rem;color:var(--mute);font-size:.85rem}
</style>
</head>
<body>
<main>
<h1>RangeProbe report</h1>
<p class="sub">Version {{.Tool.Version}} · {{.Run.Mode}} mode · started {{.Run.StartedAt}} · {{.Run.DurationMS}} ms</p>
{{if not (redacted .)}}<p class="warnbox">This report was created with --no-redact. URLs and local paths may contain secrets. Review before sharing.</p>{{end}}
{{if .Run.Interrupted}}<p class="warnbox">The run was interrupted; remaining checks were skipped.</p>{{end}}

<div class="card">
<p><span class="badge {{resultClass .Summary.Result}}">{{label .Summary.Result}}</span> <span class="sub">exit code {{.Summary.ExitCode}}</span></p>
<p>{{.Summary.Headline}}</p>
{{if .Summary.MismatchPattern}}<p><strong>Pattern:</strong> {{.Summary.MismatchPattern}}</p>{{end}}
{{if .Summary.NotPassed}}<p><strong>Key checks not passed:</strong> {{join .Summary.NotPassed ", "}}</p>{{end}}
<dl>
<dt>Target</dt><dd class="mono">{{.Run.Target}}</dd>
{{if .Endpoint.FinalURL}}<dt>Final endpoint</dt><dd class="mono">{{.Endpoint.FinalURL}}</dd>{{end}}
{{if .Reference}}<dt>Reference</dt><dd>{{.Reference.Name}}, {{.Reference.Size}} bytes. Assumed identical to the published file; not verified.</dd>{{end}}
<dt>Length</dt><dd>{{deref .Representation.Length}}{{if .Representation.LengthBasis}} <span class="sub">(reported by the server: {{.Representation.LengthBasis}})</span>{{end}}</dd>
<dt>ETag</dt><dd>{{if .Representation.ETag}}<code>{{.Representation.ETag}}</code> ({{.Representation.ETagStrength}}){{else}}none seen{{end}}</dd>
<dt>Stable</dt><dd>{{if .Representation.Stable}}no conflicting signals seen{{else}}signals changed during the run{{end}}</dd>
</dl>
{{range .Representation.Changes}}<p class="warn">{{.}}</p>{{end}}
</div>

<h2>Checks</h2>
{{range .Checks}}
<details{{if open .Status}} open{{end}}>
<summary><span class="badge {{class .Status}}">{{label .Status}}</span> <strong>{{.Title}}</strong> <code>{{.ID}}</code>{{if .Key}} <span class="sub">key</span>{{end}}</summary>
<div>
<p><strong>Claim tested:</strong> {{.Claim}}</p>
{{if .Skip}}<p class="mute"><strong>Not run:</strong> <code>{{.Skip.ID}}</code> {{.Skip.Reason}}</p>{{end}}
{{with .Request}}<p><strong>Requested</strong></p><pre>{{.Description}}</pre>{{end}}
{{with .Response}}{{if .Status}}
<p><strong>Server returned</strong> {{.Status}} <span class="sub">{{.Proto}}{{if .Chunked}}, chunked{{end}}</span></p>
<pre>{{range .Headers}}{{.Key}}: {{.Value}}
{{end}}{{if .OtherHeaders}}({{.OtherHeaders}} other headers not shown)
{{end}}</pre>
{{range .Redirects}}<p class="sub mono">redirect {{.Status}}: {{.From}} → {{.To}}</p>{{end}}
{{end}}{{end}}
{{with .Body}}
<p><strong>Body:</strong> {{.BytesRead}} bytes read (limit {{.ReadLimit}}), end state <code>{{.EndState}}</code>{{if .Declared}}, declared length {{deref .Declared}}{{end}}.{{if .SHA256}} sha256 <code>{{.SHA256}}</code>{{end}}</p>
{{with .Reference}}<p><strong>Reference comparison:</strong> {{.Compared}} bytes compared against reference bytes {{.ExpectedFirst}}–{{.ExpectedLast}};
{{if eq .Compared 0}}no body bytes arrived, so nothing was compared{{else if .Match}}identical{{else}}not identical{{if .FirstMismatch}}, first difference at offset {{deref .FirstMismatch}}, {{.MismatchCount}} differing byte(s){{end}}{{end}}.
{{if .ShiftHint}}<br>Hint: {{.ShiftHint}}.{{end}}
{{with .Fragment}}<br>Fragment at {{.Offset}} (opt-in): expected <code>{{.Expected}}</code> observed <code>{{.Observed}}</code>{{end}}</p>{{end}}
{{end}}
{{range .Findings}}
<div class="finding {{class .Kind}}">
<h4><code>{{.ID}}</code> <span class="badge {{class .Kind}}">{{label .Kind}}</span></h4>
<p style="color:var(--fg);margin:.2rem 0">{{.Message}}</p>
{{if .Evidence}}<dl style="color:var(--fg)">{{range .Evidence}}<dt>{{.Key}}</dt><dd class="mono">{{.Value}}</dd>{{end}}</dl>{{end}}
{{if .Conditions}}<p class="sub" style="margin:.2rem 0">Requires:</p><ul class="sub">{{range .Conditions}}<li>{{.}}</li>{{end}}</ul>{{end}}
{{if .Limits}}<p class="sub" style="margin:.2rem 0">Limits of this finding:</p><ul class="sub">{{range .Limits}}<li>{{.}}</li>{{end}}</ul>{{end}}
</div>
{{end}}
{{if .Verified}}<p><strong>Verified</strong></p><ul>{{range .Verified}}<li>{{.}}</li>{{end}}</ul>{{end}}
{{if .Limits}}<p class="sub">Limits: {{join .Limits " "}}</p>{{end}}
</div>
</details>
{{end}}

{{if .RunFindings}}<h2>Run-level findings</h2>
{{range .RunFindings}}<div class="card"><p><code>{{.ID}}</code> <span class="badge {{class .Kind}}">{{label .Kind}}</span></p><p>{{.Message}}</p>
{{range .Limits}}<p class="sub">{{.}}</p>{{end}}</div>{{end}}{{end}}

<h2>Verified claims</h2>
{{if .VerifiedClaims}}<ul>{{range .VerifiedClaims}}<li>{{.}}</li>{{end}}</ul>{{else}}<p class="sub">None.</p>{{end}}

<h2>Reasons for uncertainty</h2>
{{if .Uncertainty}}<ul>{{range .Uncertainty}}<li><code>{{.Source}}</code> {{if .ID}}<code>{{.ID}}</code> {{end}}{{.Text}}</li>{{end}}</ul>{{else}}<p class="sub">None recorded.</p>{{end}}

<h2>Not supported in this version</h2>
<ul>{{range .Unsupported}}<li>{{.}}</li>{{end}}</ul>

<h2>Assumptions</h2>
<ul>{{range .Assumptions}}<li>{{.}}</li>{{end}}</ul>

<h2>Run parameters</h2>
<div class="card"><dl>
<dt>Requests</dt><dd>{{.Budget.Requests}} of {{.Budget.MaxRequests}}</dd>
<dt>Body bytes read</dt><dd>{{.Budget.BytesRead}} of {{.Budget.MaxBytes}}</dd>
<dt>Per-response limit</dt><dd>{{.Run.Params.MaxBody}} bytes</dd>
<dt>Probe size</dt><dd>{{.Run.Params.ProbeSize}} bytes</dd>
<dt>Timeouts</dt><dd>request {{.Run.Params.RequestTimeoutMS}} ms, run {{.Run.Params.RunTimeoutMS}} ms</dd>
<dt>Max redirects</dt><dd>{{.Run.Params.MaxRedirects}}</dd>
<dt>If-Match preconditions</dt><dd>{{.Run.Params.Preconditions}}</dd>
<dt>User header names</dt><dd>{{if .Run.Params.HeaderNames}}{{join .Run.Params.HeaderNames ", "}} (values never recorded){{else}}none{{end}}</dd>
</dl></div>

<footer>Generated by RangeProbe {{.Tool.Version}} · JSON schema version {{.SchemaVersion}} · {{.Tool.Repository}}</footer>
</main>
</body>
</html>
`))
