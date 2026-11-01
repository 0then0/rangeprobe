// Package rangespec builds single byte-range request specifiers and parses
// Content-Range values as defined by RFC 9110 sections 14.1.2 and 14.4.
//
// Every decimal numeral is parsed without wrapping: values that do not fit in
// an int64 are reported as ErrNumberRange, never silently truncated
// (RFC 9110 section 14.1.2 requires recipients to anticipate large numerals).
package rangespec

import (
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
)

// Kind is the form of a byte range specifier.
type Kind uint8

const (
	// KindInt is "first-last".
	KindInt Kind = iota + 1
	// KindOpen is "first-".
	KindOpen
	// KindSuffix is "-N".
	KindSuffix
)

// Spec is one byte range-spec. Bounds are inclusive offsets from zero.
type Spec struct {
	Kind   Kind
	First  int64 // KindInt, KindOpen
	Last   int64 // KindInt
	Suffix int64 // KindSuffix: number of trailing bytes
}

// Int returns "first-last".
func Int(first, last int64) Spec { return Spec{Kind: KindInt, First: first, Last: last} }

// Open returns "first-".
func Open(first int64) Spec { return Spec{Kind: KindOpen, First: first} }

// Suffix returns "-n".
func Suffix(n int64) Spec { return Spec{Kind: KindSuffix, Suffix: n} }

// Valid reports whether the spec is a valid ranges-specifier member.
func (s Spec) Valid() bool {
	switch s.Kind {
	case KindInt:
		return s.First >= 0 && s.Last >= s.First
	case KindOpen:
		return s.First >= 0
	case KindSuffix:
		return s.Suffix > 0
	}
	return false
}

// Header returns the Range header field value, for example "bytes=0-99".
func (s Spec) Header() string {
	switch s.Kind {
	case KindInt:
		return fmt.Sprintf("bytes=%d-%d", s.First, s.Last)
	case KindOpen:
		return fmt.Sprintf("bytes=%d-", s.First)
	case KindSuffix:
		return fmt.Sprintf("bytes=-%d", s.Suffix)
	}
	return ""
}

// Resolve returns the inclusive interval a server selects for a
// representation of the given complete length. ok is false when the spec is
// unsatisfiable (RFC 9110 section 14.1.2): an int-range or open range whose
// first-pos is at or beyond the length, or a zero-length representation.
// A last-pos at or beyond the length is clamped to length-1.
func (s Spec) Resolve(size int64) (first, last int64, ok bool) {
	if size <= 0 || !s.Valid() {
		return 0, 0, false
	}
	switch s.Kind {
	case KindInt:
		if s.First >= size {
			return 0, 0, false
		}
		return s.First, min(s.Last, size-1), true
	case KindOpen:
		if s.First >= size {
			return 0, 0, false
		}
		return s.First, size - 1, true
	default:
		return max(0, size-s.Suffix), size - 1, true
	}
}

// SatAdd returns a+b clamped to math.MaxInt64 for non-negative operands.
func SatAdd(a, b int64) (int64, bool) {
	if a < 0 || b < 0 {
		return 0, false
	}
	if a > math.MaxInt64-b {
		return math.MaxInt64, false
	}
	return a + b, true
}

// Errors returned by ParseContentRange.
var (
	// ErrSyntax means the value does not match the Content-Range grammar.
	ErrSyntax = errors.New("malformed Content-Range")
	// ErrNumberRange means a numeral is syntactically valid but exceeds int64.
	ErrNumberRange = errors.New("Content-Range number exceeds int64")
	// ErrInvalid means the grammar matched but the value is invalid
	// (last-pos < first-pos, or complete-length <= last-pos).
	ErrInvalid = errors.New("invalid Content-Range")
	// ErrUnit means the range unit is not "bytes".
	ErrUnit = errors.New("Content-Range unit is not bytes")
)

// ContentRange is a parsed byte Content-Range value.
type ContentRange struct {
	// Unsatisfied is true for "bytes */length" (416 responses).
	Unsatisfied bool
	First, Last int64
	// Total is the complete length when TotalKnown.
	Total      int64
	TotalKnown bool
}

// Len returns the number of bytes the range covers (0 if Unsatisfied).
func (c ContentRange) Len() int64 {
	if c.Unsatisfied {
		return 0
	}
	return c.Last - c.First + 1
}

// ParseContentRange parses a Content-Range field value for the bytes unit.
func ParseContentRange(v string) (ContentRange, error) {
	v = strings.Trim(v, " \t")
	unit, rest, found := strings.Cut(v, " ")
	if !found || unit == "" || rest == "" || strings.ContainsAny(rest, " \t") {
		return ContentRange{}, ErrSyntax
	}
	if !strings.EqualFold(unit, "bytes") {
		return ContentRange{}, ErrUnit
	}
	spec, length, found := strings.Cut(rest, "/")
	if !found {
		return ContentRange{}, ErrSyntax
	}
	var cr ContentRange
	if length != "*" {
		n, err := parseNum(length)
		if err != nil {
			return ContentRange{}, err
		}
		cr.Total, cr.TotalKnown = n, true
	}
	if spec == "*" {
		if !cr.TotalKnown {
			return ContentRange{}, ErrSyntax
		}
		cr.Unsatisfied = true
		return cr, nil
	}
	a, b, found := strings.Cut(spec, "-")
	if !found {
		return ContentRange{}, ErrSyntax
	}
	first, err := parseNum(a)
	if err != nil {
		return ContentRange{}, err
	}
	last, err := parseNum(b)
	if err != nil {
		return ContentRange{}, err
	}
	cr.First, cr.Last = first, last
	if last < first || (cr.TotalKnown && cr.Total <= last) {
		return cr, ErrInvalid
	}
	return cr, nil
}

// parseNum parses 1*DIGIT into an int64. Numbers above MaxInt64 yield
// ErrNumberRange; anything that is not purely digits yields ErrSyntax.
func parseNum(s string) (int64, error) {
	if s == "" {
		return 0, ErrSyntax
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, ErrSyntax
		}
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		if errors.Is(err, strconv.ErrRange) {
			return 0, ErrNumberRange
		}
		return 0, ErrSyntax
	}
	return n, nil
}
