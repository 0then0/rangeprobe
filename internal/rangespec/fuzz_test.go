package rangespec

import "testing"

// FuzzParseContentRange checks that arbitrary input never panics and that
// accepted values satisfy the documented invariants.
func FuzzParseContentRange(f *testing.F) {
	for _, s := range []string{"bytes 0-9/10", "bytes */5", "bytes 1-2/*", "bytes 9223372036854775807-9223372036854775807/*", "x", "bytes 0-1/99999999999999999999", "bytes\t0-1/2"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		cr, err := ParseContentRange(s)
		if err != nil {
			return
		}
		if cr.First < 0 || cr.Last < 0 || cr.Total < 0 {
			t.Fatalf("negative field in %+v from %q", cr, s)
		}
		if !cr.Unsatisfied {
			if cr.Last < cr.First || (cr.TotalKnown && cr.Total <= cr.Last) {
				t.Fatalf("invalid value accepted: %+v from %q", cr, s)
			}
			if cr.Len() <= 0 {
				t.Fatalf("non-positive length for %q", s)
			}
		}
	})
}
