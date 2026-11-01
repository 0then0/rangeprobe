package plan

import (
	"math"
	"testing"

	"github.com/0then0/rangeprobe/internal/rangespec"
)

func find(items []Item, id string) Item {
	for _, it := range items {
		if it.ID == id {
			return it
		}
	}
	panic(id)
}

func TestBuildKnownLength(t *testing.T) {
	items := Build(100, Sizing{Length: 10_000, Known: true, Remote: true})
	want := map[string]string{
		"head": "bytes=0-99", "middle": "bytes=4950-5049", "tail": "bytes=9900-9999",
		"suffix": "bytes=-100", "open-ended": "bytes=9900-", "past-eof": "bytes=9950-10099",
		"unsatisfiable": "bytes=10000-", "overlap": "bytes=5000-5099", "reread": "bytes=4950-5049",
	}
	for id, hdr := range want {
		it := find(items, id)
		if it.Skip != nil {
			t.Errorf("%s skipped: %+v", id, it.Skip)
			continue
		}
		if got := it.Spec.Header(); got != hdr {
			t.Errorf("%s: %s, want %s", id, got, hdr)
		}
	}
	if find(items, "overlap").With != "middle" || !find(items, "middle").Retain {
		t.Error("overlap must compare against retained middle")
	}
}

func TestEveryPlannedRangeIsValid(t *testing.T) {
	for _, S := range []int64{1, 2, 3, 7, 100, 4097, 1 << 40, math.MaxInt64 - 5, math.MaxInt64} {
		for _, n := range []int64{1, 2, 4096} {
			for _, remote := range []bool{true, false} {
				for _, it := range Build(n, Sizing{Length: S, Known: true, Remote: remote}) {
					if it.Skip != nil {
						continue
					}
					if !it.Spec.Valid() {
						t.Errorf("S=%d n=%d %s: invalid spec %+v", S, n, it.ID, it.Spec)
					}
					if f, l, ok := it.Spec.Resolve(S); ok && it.ID != "unsatisfiable" && (f < 0 || l >= S || l < f) {
						t.Errorf("S=%d n=%d %s: resolves to %d-%d", S, n, it.ID, f, l)
					}
					if it.ID == "unsatisfiable" {
						if _, _, ok := it.Spec.Resolve(S); ok {
							t.Errorf("S=%d: unsatisfiable check is satisfiable", S)
						}
					}
				}
			}
		}
	}
}

func TestOverflowSkipsPastEOF(t *testing.T) {
	items := Build(4096, Sizing{Length: math.MaxInt64, Known: true, Remote: true})
	if find(items, "past-eof").Skip == nil || find(items, "past-eof").Skip.ID != "SKIP_OVERFLOW" {
		t.Errorf("past-eof must be skipped on overflow: %+v", find(items, "past-eof"))
	}
	if u := find(items, "unsatisfiable"); u.Skip != nil || u.Spec != rangespec.Open(math.MaxInt64) {
		t.Errorf("unsatisfiable at MaxInt64: %+v", u)
	}
}

func TestReferenceOnlyLengthIsNotRemote(t *testing.T) {
	items := Build(100, Sizing{Length: 5000, Known: true, Remote: false})
	if u := find(items, "unsatisfiable"); u.Skip == nil || u.Skip.ID != "SKIP_REMOTE_SIZE" {
		t.Errorf("reference size must not stand in for the remote size: %+v", u.Skip)
	}
}

func TestUnknownLength(t *testing.T) {
	items := Build(100, Sizing{})
	for _, id := range []string{"middle", "tail", "open-ended", "past-eof", "overlap"} {
		if find(items, id).Skip == nil {
			t.Errorf("%s must be skipped without a length", id)
		}
	}
	if find(items, "head").Skip != nil || find(items, "suffix").Skip != nil || find(items, "reread").Skip != nil {
		t.Error("head, suffix and reread work without a length")
	}
	if find(items, "reread").With != "head" {
		t.Error("reread falls back to head")
	}
}

func TestZeroLengthAndTinyFiles(t *testing.T) {
	for _, it := range Build(100, Sizing{Length: 0, Known: true, Remote: true}) {
		if it.Skip == nil || it.Skip.ID != "SKIP_ZERO_LENGTH" {
			t.Errorf("%s must skip on an empty file", it.ID)
		}
	}
	items := Build(4096, Sizing{Length: 1, Known: true, Remote: true})
	if find(items, "overlap").Skip == nil {
		t.Error("one-byte file cannot overlap")
	}
	if find(items, "head").Spec.Header() != "bytes=0-0" {
		t.Errorf("probe larger than file is clamped: %s", find(items, "head").Spec.Header())
	}
}
