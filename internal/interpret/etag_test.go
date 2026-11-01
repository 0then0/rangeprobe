package interpret

import (
	"strings"
	"testing"
)

// Expectations below come from RFC 9110 8.8.3:
//
//	entity-tag = [ weak ] opaque-tag
//	weak       = %s"W/"
//	opaque-tag = DQUOTE *etagc DQUOTE
//	etagc      = %x21 / %x23-7E / obs-text      ; obs-text = %x80-FF
func TestParseETagSyntax(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want ETagKind
	}{
		{"strong", `"a"`, ETagStrong},
		{"empty opaque-tag", `""`, ETagStrong},
		{"weak", `W/"a"`, ETagWeak},
		{"weak empty opaque-tag", `W/""`, ETagWeak},
		{"all visible etagc except dquote", `"!#$%&'()*+,-./09:;<=>?@AZ[\]^_` + "`" + `az{|}~"`, ETagStrong},
		{"comma and backslash are ordinary", `"a,b\n"`, ETagStrong},
		{"obs-text as UTF-8", "\"é中\"", ETagStrong},
		{"obs-text as lone octets", "\"\xe9\xff\x80\"", ETagStrong},
		{"weak with obs-text", "W/\"\x80\"", ETagWeak},

		{"unquoted", `abc`, ETagUnusable},
		{"starts with a quote only", `"abc`, ETagUnusable},
		{"ends with a quote only", `abc"`, ETagUnusable},
		{"a lone quote", `"`, ETagUnusable},
		{"quote followed by garbage", `"abc" trailing`, ETagUnusable},
		{"garbage before the quote", `x"abc"`, ETagUnusable},
		{"dquote inside", `"a"b"`, ETagUnusable},
		{"two tags in one value", `"a", "b"`, ETagUnusable},
		{"space inside", `"a b"`, ETagUnusable},
		{"tab inside", "\"a\tb\"", ETagUnusable},
		{"control inside", "\"a\x01\"", ETagUnusable},
		{"DEL inside", "\"a\x7f\"", ETagUnusable},
		{"NUL inside", "\"a\x00\"", ETagUnusable},
		{"lowercase weak prefix", `w/"a"`, ETagUnusable},
		{"weak prefix without tag", `W/`, ETagUnusable},
		{"weak prefix, space, tag", `W/ "a"`, ETagUnusable},
		{"weak prefix twice", `W/W/"a"`, ETagUnusable},
		{"weak prefix, unquoted", `W/a`, ETagUnusable},
		{"star is not an entity-tag", `*`, ETagUnusable},
		{"empty field value", ``, ETagUnusable},
	}
	for _, c := range cases {
		e := ParseETag([]string{c.in})
		if e.Kind != c.want {
			t.Errorf("%s: %q parsed as kind %d, want %d", c.name, c.in, e.Kind, c.want)
			continue
		}
		if c.want == ETagUnusable {
			if e.Tag != "" || e.Problem != "malformed" || !e.Present() || e.Valid() {
				t.Errorf("%s: unusable value must carry no tag: %+v", c.name, e)
			}
			continue
		}
		if e.Tag != c.in {
			t.Errorf("%s: Tag = %q, want the value exactly as received %q", c.name, e.Tag, c.in)
		}
	}
}

func TestParseETagAbsentAndRepeated(t *testing.T) {
	if e := ParseETag(nil); e.Present() || e.Kind != ETagNone {
		t.Errorf("no field: %+v", e)
	}
	for _, vals := range [][]string{
		{`"a"`, `"a"`},
		{`"a"`, `"b"`},
		{`"a"`, `W/"a"`},
		{`"a"`, `abc`},
	} {
		e := ParseETag(vals)
		if e.Kind != ETagUnusable || e.Problem != "repeated" || e.Tag != "" {
			t.Errorf("%q: repeated field must be unusable, got %+v", vals, e)
		}
	}
}

func TestParseETagSizeLimit(t *testing.T) {
	atLimit := `"` + strings.Repeat("x", 7998) + `"` // 8000 octets
	if e := ParseETag([]string{atLimit}); e.Kind != ETagStrong || e.Tag != atLimit {
		t.Errorf("8000 octets must be accepted whole: kind %d, %d octets kept", e.Kind, len(e.Tag))
	}
	over := `"` + strings.Repeat("x", 7999) + `"` // 8001 octets
	e := ParseETag([]string{over})
	if e.Kind != ETagUnusable || e.Problem != "too long" || e.Tag != "" {
		t.Errorf("8001 octets must lose all evidential force, not be shortened: %+v", e)
	}
}

// The opaque-tag is compared octet by octet: no case folding, Unicode
// normalisation or unescaping (RFC 9110 8.8.3.2).
func TestOpaqueTagIsNeverTransformed(t *testing.T) {
	cases := []struct{ name, a, b string }{
		{"case", `"abc"`, `"ABC"`},
		{"NFC vs NFD", "\"é\"", "\"é\""},
		{"backslash escape vs the character", `"\x41"`, `"A"`},
		{"percent escape vs the character", `"%41"`, `"A"`},
		{"UTF-8 vs the same code point as one octet", "\"é\"", "\"\xe9\""},
		{"trailing difference after 240 equal characters",
			`"` + strings.Repeat("x", 240) + `0001"`, `"` + strings.Repeat("x", 240) + `0002"`},
		{"difference in the last octet of 7000", `"` + strings.Repeat("y", 6999) + `a"`, `"` + strings.Repeat("y", 6999) + `b"`},
	}
	for _, c := range cases {
		a, b := fp(c.a, 10, ""), fp(c.b, 10, "")
		if ev, why := Compare(a, b); ev != EvidenceConflict || len(why) != 1 {
			t.Errorf("%s: %q vs %q gave %v %v, want conflict", c.name, c.a, c.b, ev, why)
		}
		if ev, _ := Compare(a, a); ev != EvidenceStrong {
			t.Errorf("%s: identical tags must be strong evidence, got %v", c.name, ev)
		}
	}
}

func TestValidatorsThatCannotBeComparedGiveNoStrongEvidence(t *testing.T) {
	good := fp(`"a"`, 10, "")
	cases := []struct {
		name string
		a, b Fingerprint
		want Evidence
	}{
		{"strong with strong", good, good, EvidenceStrong},
		{"malformed on one side", good, fp(`"a`, 10, ""), EvidenceWeak},
		{"malformed on both sides", fp(`a`, 10, ""), fp(`a`, 10, ""), EvidenceWeak},
		{"malformed value that looks like the other", fp(`"a b"`, 10, ""), fp(`"a b"`, 10, ""), EvidenceWeak},
		{"oversize on both sides", fp(`"`+strings.Repeat("x", 9000)+`"`, 10, ""), fp(`"`+strings.Repeat("x", 9000)+`"`, 10, ""), EvidenceWeak},
		{"oversize against a different oversize", fp(`"`+strings.Repeat("x", 9000)+`1"`, 10, ""), fp(`"`+strings.Repeat("x", 9000)+`2"`, 10, ""), EvidenceWeak},
		{"weak with weak", fp(`W/"a"`, 10, ""), fp(`W/"a"`, 10, ""), EvidenceWeak},
		{"weak against different strong", fp(`W/"a"`, 10, ""), fp(`"b"`, 10, ""), EvidenceConflict},
	}
	rep := Fingerprint{Total: 10, TotalKnown: true, Encoding: "identity", ETag: ParseETag([]string{`"a"`, `"a"`})}
	cases = append(cases,
		struct {
			name string
			a, b Fingerprint
			want Evidence
		}{"repeated field with the same value on both sides", rep, rep, EvidenceWeak},
		struct {
			name string
			a, b Fingerprint
			want Evidence
		}{"repeated field against a good tag", rep, good, EvidenceWeak})
	for _, c := range cases {
		got, why := Compare(c.a, c.b)
		if got != c.want {
			t.Errorf("%s: %v, want %v (%v)", c.name, got, c.want, why)
		}
	}
	if rep.HasStrongETag() || fp(`W/"a"`, 1, "").HasStrongETag() || fp(`a`, 1, "").HasStrongETag() || !good.HasStrongETag() {
		t.Error("HasStrongETag disagrees with the syntax")
	}
}

// Shortening and escaping apply to the display form only.
func TestDisplayDoesNotAffectSemantics(t *testing.T) {
	long := `"` + strings.Repeat("x", 240) + `0001"`
	e := ParseETag([]string{long})
	if e.Tag != long {
		t.Fatalf("protocol value was altered: %d octets of %d", len(e.Tag), len(long))
	}
	if len(e.Display()) >= len(long) || !strings.Contains(e.Display(), "…") {
		t.Errorf("a long value must be shortened for display: %q", e.Display())
	}
	other := ParseETag([]string{`"` + strings.Repeat("x", 240) + `0002"`})
	if e.Display() == other.Display() {
		t.Errorf("values that differ only at the end must not look alike: %q", e.Display())
	}

	// Two different valid tags with an identical display form.
	escaped := `"` + `\` + `u200b` + `"` // ASCII: backslash, u, 2, 0, 0, b
	zeroWidth := "\"\xe2\x80\x8b\""      // U+200B, a format character shown as the escape above
	a, b := ParseETag([]string{escaped}), ParseETag([]string{zeroWidth})
	if a.Display() != b.Display() {
		t.Fatalf("test premise: displays %q and %q should coincide", a.Display(), b.Display())
	}
	if ev, _ := Compare(Fingerprint{ETag: a}, Fingerprint{ETag: b}); ev != EvidenceConflict {
		t.Errorf("equal displays must not make different tags equal: %v", ev)
	}
	if b.Tag != zeroWidth {
		t.Errorf("Tag must keep the raw octets, got %q", b.Tag)
	}
}

func TestDisplayETagIsSafeToPrint(t *testing.T) {
	cases := []string{
		"\"a\x1b[31m\"",
		"\"‮\"",
		"\"\xff\xfe\"",
		"\"<script>alert(1)</script>\"",
		"abc\r\nX-Injected: 1",
		strings.Repeat("é", 5000),
	}
	for _, in := range cases {
		got := DisplayETag(in)
		for _, r := range got {
			if r < 0x20 || r == 0x7f || r == 0x202e || r == 0xfffd {
				t.Errorf("%q: display %q holds an unsafe character %U", in, got, r)
			}
		}
		if len([]rune(got)) > 400 {
			t.Errorf("%q: display is %d runes long", in, len([]rune(got)))
		}
	}
	if got := DisplayETag(`"v1"`); got != `"v1"` {
		t.Errorf("a short value must be shown unchanged, got %q", got)
	}
	// Untrusted bytes in unusable and repeated values are escaped too.
	if got := ParseETag([]string{"\"a\x1b\""}).Display(); strings.ContainsRune(got, 0x1b) {
		t.Errorf("unusable value displayed raw: %q", got)
	}
	if got := ParseETag([]string{"\"a\"", "\x07"}).Display(); strings.ContainsRune(got, 7) {
		t.Errorf("repeated value displayed raw: %q", got)
	}
}

// A conflict reason keeps its old bound of 80 runes per ETag, yet two long
// tags that differ only at the end stay distinguishable in it.
func TestConflictReasonIsBoundedAndDistinguishes(t *testing.T) {
	a := fp(`"`+strings.Repeat("x", 240)+`0001"`, 10, "")
	b := fp(`"`+strings.Repeat("x", 240)+`0002"`, 10, "")
	ev, why := Compare(a, b)
	if ev != EvidenceConflict || len(why) != 1 {
		t.Fatalf("%v %v", ev, why)
	}
	// 80 runes per ETag plus at most 40 for the cut marker and the digest.
	if n := len([]rune(why[0])); n > 2*(80+40)+len("ETag  vs ") {
		t.Errorf("reason is %d runes long: %q", n, why[0])
	}
	if strings.Contains(why[0], strings.Repeat("x", 100)) {
		t.Errorf("reason shows more than 80 runes of an ETag: %q", why[0])
	}
	x, y, ok := strings.Cut(strings.TrimPrefix(why[0], "ETag "), " vs ")
	if !ok || x == y {
		t.Errorf("the two sides of the reason look alike: %q", why[0])
	}
}
