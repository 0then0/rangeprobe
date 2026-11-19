// Package redact removes sensitive values from strings that end up in
// reports, and neutralises untrusted text (control and bidi characters).
package redact

import (
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Placeholder replaces a redacted value.
const Placeholder = "REDACTED"

// Redactor rewrites URLs, paths and free text. The zero value redacts
// nothing; use New.
type Redactor struct {
	// Locations controls URL query/userinfo and local path redaction.
	// Header secrets (Secrets) are always removed from free text.
	Locations   bool
	secrets     []string
	rawURLs     []string
	queryValues *strings.Replacer
}

// New returns a Redactor. locations enables URL and path redaction.
func New(locations bool) *Redactor { return &Redactor{Locations: locations} }

// AddSecret registers a value that must never appear in output.
func (r *Redactor) AddSecret(v string) {
	if len(v) >= 3 {
		r.secrets = append(r.secrets, v)
		sort.Slice(r.secrets, func(i, j int) bool { return len(r.secrets[i]) > len(r.secrets[j]) })
	}
}

// AddURL registers a raw URL so that Text can replace it verbatim.
func (r *Redactor) AddURL(raw string) {
	if raw != "" {
		r.rawURLs = append(r.rawURLs, raw)
		sort.Slice(r.rawURLs, func(i, j int) bool { return len(r.rawURLs[i]) > len(r.rawURLs[j]) })
	}
}

// SetURLQueryValues masks URL query values when they appear outside their URL,
// for example in response headers. It applies only with location redaction on.
func (r *Redactor) SetURLQueryValues(urls ...string) {
	if !r.Locations {
		return
	}
	var values []string
	seen := make(map[string]bool)
	for _, raw := range urls {
		u, err := url.Parse(raw)
		if err != nil {
			continue
		}
		for field := range strings.SplitSeq(u.RawQuery, "&") {
			_, value, _ := strings.Cut(field, "=")
			decoded, _ := url.QueryUnescape(value)
			for _, secret := range [2]string{value, decoded} {
				if len(secret) >= 3 && !seen[secret] {
					values = append(values, secret)
					seen[secret] = true
				}
			}
		}
	}
	sort.Slice(values, func(i, j int) bool { return len(values[i]) > len(values[j]) })
	pairs := make([]string, 0, 2*len(values))
	for _, value := range values {
		pairs = append(pairs, value, Placeholder)
	}
	r.queryValues = strings.NewReplacer(pairs...)
}

// ReportURL applies URL redaction and also masks known secrets in the path.
func (r *Redactor) ReportURL(raw string) string {
	if u, err := url.Parse(raw); err == nil {
		if path := r.maskSecrets(u.Path); path != u.Path {
			u.Path, u.RawPath = path, ""
			raw = u.String()
		}
	}
	return r.maskSecrets(r.URL(raw))
}

// URL returns a publishable form of raw: no userinfo, no fragment, and query
// values replaced by REDACTED (keys are kept for diagnosis).
func (r *Redactor) URL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" {
		return Clean("<unparseable URL>", 64)
	}
	if !r.Locations {
		u.Fragment, u.RawFragment = "", ""
		u.User = nil
		return Clean(u.String(), 2048)
	}
	u.User = nil
	u.Fragment, u.RawFragment = "", ""
	if u.RawQuery != "" {
		parts := strings.Split(u.RawQuery, "&")
		for i, p := range parts {
			k, _, _ := strings.Cut(p, "=")
			if k == "" {
				parts[i] = Placeholder
				continue
			}
			parts[i] = k + "=" + Placeholder
		}
		u.RawQuery = strings.Join(parts, "&")
	}
	// Opaque and RawQuery are rendered verbatim by String.
	return Clean(u.String(), 2048)
}

// Path reduces a local filesystem path to its base name when redacting.
func (r *Redactor) Path(p string) string {
	if !r.Locations {
		return Clean(p, 1024)
	}
	i := strings.LastIndexAny(p, `/\`)
	return Clean(p[i+1:], 255)
}

var urlInText = regexp.MustCompile(`https?://[^\s"'<>]+`)

// Text cleans free text such as error messages: registered raw URLs and any
// other URL found in it are redacted, registered secrets are removed.
func (r *Redactor) Text(s string) string {
	return r.text(s, r.URL)
}

// ReportText also masks known secrets in the decoded paths of embedded URLs.
func (r *Redactor) ReportText(s string) string {
	return r.text(s, r.ReportURL)
}

func (r *Redactor) text(s string, cleanURL func(string) string) string {
	for _, raw := range r.rawURLs {
		s = strings.ReplaceAll(s, raw, cleanURL(raw))
	}
	s = urlInText.ReplaceAllStringFunc(s, func(m string) string {
		trimmed := strings.TrimRight(m, ".,;:)")
		return cleanURL(trimmed) + m[len(trimmed):]
	})
	return Clean(r.maskSecrets(s), 1024)
}

func (r *Redactor) maskSecrets(s string) string {
	if r.queryValues != nil {
		s = r.queryValues.Replace(s)
	}
	for _, sec := range r.secrets {
		s = strings.ReplaceAll(s, sec, Placeholder)
	}
	return s
}

// Clean makes untrusted text safe to print: invalid UTF-8, control
// characters and bidi/format controls become visible \u escapes, and the
// result is truncated to max runes. max <= 0 means no limit.
func Clean(s string, max int) string {
	var b strings.Builder
	n := 0
	for len(s) > 0 {
		if max > 0 && n >= max {
			fmt.Fprintf(&b, "…(+%d bytes)", len(s))
			break
		}
		r, size := utf8.DecodeRuneInString(s)
		switch {
		case r == utf8.RuneError && size == 1:
			fmt.Fprintf(&b, `\x%02x`, s[0])
		case r == '\t':
			b.WriteRune(' ')
		case unicode.IsControl(r), unicode.Is(unicode.Cf, r), r == '\u2028', r == '\u2029':
			if r > 0xFFFF {
				fmt.Fprintf(&b, `\U%08x`, r)
			} else {
				fmt.Fprintf(&b, `\u%04x`, r)
			}
		default:
			b.WriteRune(r)
		}
		s = s[size:]
		n++
	}
	return b.String()
}
