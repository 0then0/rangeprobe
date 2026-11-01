// Package plan decides which single-range probes to run. It builds a fixed,
// bounded list of checks from the probe size and the representation length
// and records why a check cannot run. It performs no I/O.
package plan

import (
	"fmt"

	"github.com/0then0/rangeprobe/internal/model"
	"github.com/0then0/rangeprobe/internal/rangespec"
)

// Item is one planned probe.
type Item struct {
	ID    string
	Title string
	// Key marks checks that random-access readers (Parquet footers, media
	// seeking, resumed downloads) depend on. A skipped or failed key check
	// prevents a complete PASS.
	Key   bool
	Spec  rangespec.Spec
	Claim string

	// Retain keeps the body so a later check can compare against it.
	Retain bool
	// Relation, when set, compares this check's body with the retained body
	// of the check named by With.
	Relation string
	With     string

	// ExpectBytes is the body size a conforming server sends, used for
	// budget admission only. Actual reads are always capped separately.
	ExpectBytes int64
	// NeedsRemoteSize marks checks that require a length reported by the
	// server, not merely assumed from the reference file.
	NeedsRemoteSize bool

	// Skip is set when the check cannot run for static reasons.
	Skip *model.Skip
}

// Sizing is what is known about the representation length when planning.
type Sizing struct {
	// Length is the length used to place offsets; Known is false when none
	// is available.
	Length int64
	Known  bool
	// Remote is true when the server reported the length (as opposed to
	// taking it from the reference file).
	Remote bool
}

func skip(id, reason string) *model.Skip { return &model.Skip{ID: id, Reason: reason} }

// FirstByte returns the discovery probe, always sent first.
func FirstByte() Item {
	return Item{
		ID: "first-byte", Title: "First byte", Key: true, Spec: rangespec.Int(0, 0),
		Claim:       "bytes=0-0 returns exactly the first byte with a consistent Content-Range",
		ExpectBytes: 1,
	}
}

// Build returns the checks that follow the discovery probe.
func Build(probe int64, sz Sizing) []Item {
	n := max(probe, 1)
	items := []Item{{
		ID: "head", Title: "Range at the start", Key: true,
		Claim: "a small range at the start returns the requested bytes",
	}, {
		ID: "middle", Title: "Range in the middle", Key: true, Retain: true,
		Claim: "a range in the middle of the file returns the requested bytes",
	}, {
		ID: "tail", Title: "Range at the end", Key: true,
		Claim: "the last bytes, requested by explicit offsets, are returned",
	}, {
		ID: "suffix", Title: "Suffix range", Key: true,
		Claim: "a suffix range returns the last N bytes",
	}, {
		ID: "open-ended", Title: "Open-ended range",
		Claim: "an open-ended range near the end returns everything up to EOF",
	}, {
		ID: "past-eof", Title: "Range ending beyond EOF",
		Claim: "a last-pos beyond EOF is clamped to the representation length",
	}, {
		ID: "unsatisfiable", Title: "Unsatisfiable range",
		Claim: "a range starting at EOF is answered with 416 (or a full 200)", NeedsRemoteSize: true,
	}, {
		ID: "overlap", Title: "Overlapping ranges", Relation: "overlap", With: "middle", Retain: true,
		Claim: "two overlapping ranges return identical bytes for their common interval",
	}, {
		ID: "reread", Title: "Re-read", Relation: "reread", With: "middle", Retain: true,
		Claim: "re-reading a range returns the same bytes",
	}}
	byID := func(id string) *Item {
		for i := range items {
			if items[i].ID == id {
				return &items[i]
			}
		}
		return nil
	}
	set := func(id string, s rangespec.Spec, expect int64) {
		it := byID(id)
		it.Spec, it.ExpectBytes = s, expect
	}
	skipAll := func(sk *model.Skip, ids ...string) {
		for _, id := range ids {
			byID(id).Skip = sk
		}
	}

	// Checks that work without a known length.
	set("head", rangespec.Int(0, n-1), n)
	set("suffix", rangespec.Suffix(n), n)

	switch {
	case sz.Known && sz.Length == 0:
		skipAll(skip("SKIP_ZERO_LENGTH", "the representation is empty, so no range can select bytes"),
			"head", "middle", "tail", "suffix", "open-ended", "past-eof", "unsatisfiable", "overlap", "reread")
		return items
	case !sz.Known:
		skipAll(skip("SKIP_SIZE_UNKNOWN", "no length from the server or the reference file; offsets cannot be placed safely"),
			"middle", "tail", "open-ended", "past-eof", "overlap")
		skipAll(skip("SKIP_REMOTE_SIZE", "the server reported no representation length, so EOF cannot be established"), "unsatisfiable")
		// A re-read of the head still tests repeatability.
		it := byID("reread")
		it.With, it.Spec, it.ExpectBytes = "head", rangespec.Int(0, n-1), n
		byID("head").Retain = true
		return items
	}

	S := sz.Length
	m := min(n, S)
	set("head", rangespec.Int(0, m-1), m)
	set("suffix", rangespec.Suffix(m), m)
	mStart := max(0, S/2-m/2)
	set("middle", rangespec.Int(mStart, mStart+m-1), m)
	set("tail", rangespec.Int(S-m, S-1), m)
	set("open-ended", rangespec.Open(S-m), m)

	half := max(m/2, 1)
	if last, ok := rangespec.SatAdd(S-1, m); ok {
		set("past-eof", rangespec.Int(S-half, last), half)
	} else {
		byID("past-eof").Skip = skip("SKIP_OVERFLOW", fmt.Sprintf("last-pos for a length of %d would exceed 9223372036854775807", S))
	}

	if sz.Remote {
		set("unsatisfiable", rangespec.Open(S), 0)
	} else {
		byID("unsatisfiable").Skip = skip("SKIP_REMOTE_SIZE", "the length comes from the reference file only; the server has not reported one, so EOF is not established")
	}

	bStart := min(mStart+half, S-1)
	bEnd := min(bStart+m-1, S-1)
	if m < 2 || bStart > mStart+m-1 {
		byID("overlap").Skip = skip("SKIP_TOO_SMALL", "the probe size or file is too small to form two overlapping ranges")
	} else {
		set("overlap", rangespec.Int(bStart, bEnd), bEnd-bStart+1)
	}
	set("reread", rangespec.Int(mStart, mStart+m-1), m)
	return items
}
