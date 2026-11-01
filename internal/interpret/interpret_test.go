package interpret

import (
	"testing"

	"github.com/0then0/rangeprobe/internal/model"
)

func fp(etag string, total int64, lm string) Fingerprint {
	f := Fingerprint{Total: total, TotalKnown: total >= 0, LastModified: lm, Encoding: "identity"}
	if etag != "" {
		f.HasETag, f.ETag = true, etag
		f.ETagWeak = len(etag) > 1 && etag[:2] == "W/"
	}
	return f
}

func TestCompare(t *testing.T) {
	cases := []struct {
		name string
		a, b Fingerprint
		want Evidence
	}{
		{"same strong etag", fp(`"a"`, 10, ""), fp(`"a"`, 10, ""), EvidenceStrong},
		{"same weak etag is not strong", fp(`W/"a"`, 10, ""), fp(`W/"a"`, 10, ""), EvidenceWeak},
		{"strong vs weak with same tag", fp(`"a"`, 10, ""), fp(`W/"a"`, 10, ""), EvidenceWeak},
		{"no validators, same length", fp("", 10, ""), fp("", 10, ""), EvidenceWeak},
		{"equal Last-Modified alone is weak", fp("", 10, "Mon"), fp("", 10, "Mon"), EvidenceWeak},
		{"etag differs", fp(`"a"`, 10, ""), fp(`"b"`, 10, ""), EvidenceConflict},
		{"weak etag differs", fp(`W/"a"`, 10, ""), fp(`W/"b"`, 10, ""), EvidenceConflict},
		{"length differs", fp(`"a"`, 10, ""), fp(`"a"`, 11, ""), EvidenceConflict},
		{"last-modified differs", fp("", 10, "Mon"), fp("", 10, "Tue"), EvidenceConflict},
		{"unknown length is not a conflict", fp(`"a"`, -1, ""), fp(`"a"`, 11, ""), EvidenceStrong},
		{"validator appearing is not a conflict", fp("", 10, ""), fp(`"a"`, 10, ""), EvidenceWeak},
	}
	for _, c := range cases {
		got, why := Compare(c.a, c.b)
		if got != c.want {
			t.Errorf("%s: %v, want %v (%v)", c.name, got, c.want, why)
		}
		if (got == EvidenceConflict) != (len(why) > 0) {
			t.Errorf("%s: reasons %v do not match verdict", c.name, why)
		}
	}
}

func TestRelate(t *testing.T) {
	a := &Retained{First: 100, Last: 109, Body: []byte("0123456789"), FP: fp(`"v"`, 1000, "")}
	b := &Retained{First: 105, Last: 114, Body: []byte("56789abcde"), FP: fp(`"v"`, 1000, "")}
	fs, ver := Relate(RelOverlap, a, b)
	if len(fs) != 0 || len(ver) != 1 {
		t.Fatalf("equal overlap: %+v %v", fs, ver)
	}
	b.Body = []byte("56X89abcde")
	fs, _ = Relate(RelOverlap, a, b)
	if len(fs) != 1 || fs[0].ID != "OVERLAP_INCONSISTENT" || fs[0].Kind != model.KindViolation {
		t.Fatalf("strong mismatch: %+v", fs)
	}
	b.FP = fp(`W/"v"`, 1000, "")
	if fs, _ = Relate(RelOverlap, a, b); fs[0].ID != "CONSISTENCY_UNATTRIBUTED" || fs[0].Kind != model.KindInconclusive {
		t.Fatalf("weak mismatch: %+v", fs)
	}
	b.FP = fp(`"w"`, 1000, "")
	if fs, _ = Relate(RelOverlap, a, b); fs[0].ID != "REPRESENTATION_CHANGED" {
		t.Fatalf("conflict: %+v", fs)
	}
	far := &Retained{First: 500, Last: 509, Body: make([]byte, 10), FP: a.FP}
	if fs, _ = Relate(RelOverlap, a, far); fs[0].ID != "RELATION_INPUT_UNAVAILABLE" {
		t.Fatalf("disjoint: %+v", fs)
	}
	if fs, _ = Relate(RelReread, nil, a); fs[0].ID != "RELATION_INPUT_UNAVAILABLE" {
		t.Fatalf("missing input: %+v", fs)
	}
}

func TestApplyStabilityDowngradesOnlyIdentityFindings(t *testing.T) {
	base := fp(`"a"`, 10, "")
	other := fp(`"b"`, 10, "")
	fs := []model.Finding{
		model.NewFinding("BYTES_MISMATCH_REFERENCE", "m").AsIdentity(),
		model.NewFinding("BODY_TRUNCATED", "t"),
	}
	out := ApplyStability(fs, &base, other)
	if out[0].Kind != model.KindInconclusive || out[1].Kind != model.KindViolation {
		t.Errorf("kinds %s %s", out[0].Kind, out[1].Kind)
	}
	if out[len(out)-1].ID != "REPRESENTATION_CHANGED" {
		t.Error("REPRESENTATION_CHANGED not appended")
	}
	if same := ApplyStability(fs, &base, base); len(same) != 2 || same[0].Kind != model.KindByteMismatch {
		t.Error("unchanged representation must keep verdicts")
	}
}
