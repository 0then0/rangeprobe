package interpret

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/0then0/rangeprobe/internal/redact"
)

// ETagKind classifies the ETag field of one response.
type ETagKind int

// ETag kinds.
const (
	// ETagNone means the response had no ETag field.
	ETagNone ETagKind = iota
	// ETagStrong is a well-formed entity-tag without the W/ prefix.
	ETagStrong
	// ETagWeak is a well-formed entity-tag with the W/ prefix.
	ETagWeak
	// ETagUnusable means a field was present but cannot be used as a
	// validator: it is malformed, repeated or longer than maxETagLen. It
	// proves nothing and is never sent in If-Match.
	ETagUnusable
)

// maxETagLen bounds the octets accepted as one entity-tag. RFC 9110 4.1
// asks recipients to handle at least 8000 octets in protocol elements. A
// longer value is treated as unusable rather than shortened: two values
// that merely begin alike must never be compared as equal.
const maxETagLen = 8000

// etagShowMax is the number of runes of an ETag shown in reports.
const etagShowMax = 200

// ETag is the ETag field of one response. Tag is the protocol value and the
// only input to comparison and If-Match. The display form is separate: it is
// shortened, escaped and has no protocol meaning.
type ETag struct {
	Kind ETagKind
	// Tag is the entity-tag exactly as received, including a W/ prefix and
	// the quotes. Set only for ETagStrong and ETagWeak.
	Tag string
	// Problem says why an ETagUnusable value is unusable: "repeated",
	// "malformed" or "too long".
	Problem string

	shown string
}

// ParseETag interprets the values of the ETag field of a response
// (RFC 9110 8.8.3):
//
//	ETag       = entity-tag
//	entity-tag = [ weak ] opaque-tag
//	weak       = %s"W/"
//	opaque-tag = DQUOTE *etagc DQUOTE
//	etagc      = %x21 / %x23-7E / obs-text
//
// The opaque value is never decoded, normalised or case-folded.
func ParseETag(values []string) ETag {
	switch len(values) {
	case 0:
		return ETag{}
	case 1:
	default:
		return ETag{Kind: ETagUnusable, Problem: "repeated", shown: DisplayETag(strings.Join(values, " | "))}
	}
	v := values[0]
	e := ETag{shown: DisplayETag(v)}
	switch {
	case len(v) > maxETagLen:
		e.Kind, e.Problem = ETagUnusable, "too long"
	case !entityTag(v):
		e.Kind, e.Problem = ETagUnusable, "malformed"
	case strings.HasPrefix(v, "W/"):
		e.Kind, e.Tag = ETagWeak, v
	default:
		e.Kind, e.Tag = ETagStrong, v
	}
	return e
}

// entityTag reports whether s matches entity-tag.
func entityTag(s string) bool {
	s = strings.TrimPrefix(s, "W/")
	if len(s) < 2 || s[0] != '"' || s[len(s)-1] != '"' {
		return false
	}
	for i := 1; i < len(s)-1; i++ {
		if c := s[i]; c != 0x21 && (c < 0x23 || c == 0x7F) {
			return false
		}
	}
	return true
}

// Present reports whether the response had an ETag field of any kind.
func (e ETag) Present() bool { return e.Kind != ETagNone }

// Valid reports whether Tag holds a well-formed entity-tag.
func (e ETag) Valid() bool { return e.Kind == ETagStrong || e.Kind == ETagWeak }

// opaque returns the opaque-tag, which both comparison functions compare
// character by character (RFC 9110 8.8.3.2).
func (e ETag) opaque() string { return strings.TrimPrefix(e.Tag, "W/") }

// Display is the text shown for the ETag in diagnostics and reports.
func (e ETag) Display() string { return e.shown }

// DisplayETag makes an ETag value (or any similar header value) safe and
// short enough for a report: control and bidi characters are escaped and
// anything beyond etagShowMax runes is cut off. A cut value carries a digest
// of the whole value so that two long values that differ only at the end do
// not look identical. The result is for people and must never be used as a
// protocol value.
func DisplayETag(s string) string { return displayETag(s, etagShowMax) }

func displayETag(s string, max int) string {
	shown := redact.Clean(s, max)
	if utf8.RuneCountInString(s) > max {
		sum := sha256.Sum256([]byte(s))
		shown += fmt.Sprintf(" [sha256 %x]", sum[:6])
	}
	return shown
}
