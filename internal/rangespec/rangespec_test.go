package rangespec

import (
	"errors"
	"math"
	"testing"
)

func TestHeader(t *testing.T) {
	cases := map[string]Spec{
		"bytes=0-0":    Int(0, 0),
		"bytes=10-":    Open(10),
		"bytes=-4096":  Suffix(4096),
		"bytes=5-1023": Int(5, 1023),
	}
	for want, s := range cases {
		if got := s.Header(); got != want {
			t.Errorf("Header() = %q, want %q", got, want)
		}
	}
}

func TestResolve(t *testing.T) {
	type res struct {
		first, last int64
		ok          bool
	}
	cases := []struct {
		name string
		spec Spec
		size int64
		want res
	}{
		{"inside", Int(10, 19), 100, res{10, 19, true}},
		{"last beyond EOF is clamped", Int(90, 500), 100, res{90, 99, true}},
		{"first at EOF is unsatisfiable", Int(100, 120), 100, res{0, 0, false}},
		{"open", Open(95), 100, res{95, 99, true}},
		{"open at EOF", Open(100), 100, res{0, 0, false}},
		{"suffix", Suffix(10), 100, res{90, 99, true}},
		{"suffix longer than representation", Suffix(1000), 100, res{0, 99, true}},
		{"zero length", Suffix(1), 0, res{0, 0, false}},
		{"huge offsets", Int(math.MaxInt64-1, math.MaxInt64), math.MaxInt64, res{math.MaxInt64 - 1, math.MaxInt64 - 1, true}},
	}
	for _, c := range cases {
		f, l, ok := c.spec.Resolve(c.size)
		if (res{f, l, ok}) != c.want {
			t.Errorf("%s: got %v %v %v, want %+v", c.name, f, l, ok, c.want)
		}
	}
}

func TestSatAdd(t *testing.T) {
	if v, ok := SatAdd(math.MaxInt64-1, 5); ok || v != math.MaxInt64 {
		t.Errorf("overflow not clamped: %d %v", v, ok)
	}
	if v, ok := SatAdd(1, 2); !ok || v != 3 {
		t.Errorf("SatAdd(1,2) = %d %v", v, ok)
	}
}

func TestParseContentRange(t *testing.T) {
	good := []struct {
		in   string
		want ContentRange
	}{
		{"bytes 0-499/1234", ContentRange{First: 0, Last: 499, Total: 1234, TotalKnown: true}},
		{"BYTES 42-1233/*", ContentRange{First: 42, Last: 1233}},
		{"bytes */1234", ContentRange{Unsatisfied: true, Total: 1234, TotalKnown: true}},
		{" bytes 9223372036854775806-9223372036854775806/9223372036854775807 ", ContentRange{First: math.MaxInt64 - 1, Last: math.MaxInt64 - 1, Total: math.MaxInt64, TotalKnown: true}},
	}
	for _, c := range good {
		got, err := ParseContentRange(c.in)
		if err != nil || got != c.want {
			t.Errorf("%q: got %+v, %v; want %+v", c.in, got, err, c.want)
		}
	}
	bad := []struct {
		in  string
		err error
	}{
		{"", ErrSyntax},
		{"bytes", ErrSyntax},
		{"bytes 1-2", ErrSyntax},
		{"bytes 1-2/x", ErrSyntax},
		{"bytes -1-2/10", ErrSyntax},
		{"bytes +1-2/10", ErrSyntax},
		{"bytes 1- 2/10", ErrSyntax},
		{"bytes */*", ErrSyntax},
		{"items 1-2/10", ErrUnit},
		{"bytes 5-4/10", ErrInvalid},
		{"bytes 0-9/10", nil}, // valid: total == last+1
		{"bytes 0-10/10", ErrInvalid},
		{"bytes 0-9/9", ErrInvalid},
		{"bytes 0-9223372036854775808/*", ErrNumberRange},
		{"bytes 0-1/99999999999999999999999", ErrNumberRange},
		{"bytes */18446744073709551616", ErrNumberRange},
	}
	for _, c := range bad {
		_, err := ParseContentRange(c.in)
		if !errors.Is(err, c.err) && !(c.err == nil && err == nil) {
			t.Errorf("%q: err = %v, want %v", c.in, err, c.err)
		}
	}
}
