package interpret

import (
	"fmt"

	"github.com/0then0/rangeprobe/internal/redact"
)

// Fingerprint holds the signals one response gives about which
// representation it belongs to. Equal signals never prove identity; they only
// fail to contradict it.
type Fingerprint struct {
	ETag         ETag
	LastModified string
	Total        int64
	TotalKnown   bool
	// Encoding is "identity" or the content coding for 200/206 responses;
	// empty when not applicable.
	Encoding string
}

// Evidence is how strongly two fingerprints suggest one representation.
type Evidence int

const (
	// EvidenceConflict means some signal differs: treat as different
	// representations (or an unstable one).
	EvidenceConflict Evidence = iota
	// EvidenceWeak means nothing conflicts but no shared strong validator
	// exists.
	EvidenceWeak
	// EvidenceStrong means both carry the same strong ETag and nothing else
	// conflicts. RFC 9110 8.8.1 still only promises byte equality while the
	// server's validators are correct.
	EvidenceStrong
)

func (e Evidence) String() string {
	switch e {
	case EvidenceStrong:
		return "strong (same strong ETag)"
	case EvidenceWeak:
		return "weak (no conflicting signal, no shared strong ETag)"
	}
	return "conflict"
}

// Compare relates two fingerprints. The returned reasons explain a conflict.
func Compare(a, b Fingerprint) (Evidence, []string) {
	var why []string
	if a.TotalKnown && b.TotalKnown && a.Total != b.Total {
		why = append(why, fmt.Sprintf("complete length %d vs %d", a.Total, b.Total))
	}
	// Unusable ETags are neither equal nor different: they cannot be compared.
	// Only the reason text is shortened; the comparison uses the whole tag.
	if a.ETag.Valid() && b.ETag.Valid() && a.ETag.opaque() != b.ETag.opaque() {
		why = append(why, fmt.Sprintf("ETag %s vs %s", displayETag(a.ETag.Tag, 80), displayETag(b.ETag.Tag, 80)))
	}
	if a.LastModified != "" && b.LastModified != "" && a.LastModified != b.LastModified {
		why = append(why, fmt.Sprintf("Last-Modified %s vs %s", redact.Clean(a.LastModified, 40), redact.Clean(b.LastModified, 40)))
	}
	if a.Encoding != "" && b.Encoding != "" && a.Encoding != b.Encoding {
		why = append(why, fmt.Sprintf("content coding %s vs %s", redact.Clean(a.Encoding, 40), redact.Clean(b.Encoding, 40)))
	}
	if len(why) > 0 {
		return EvidenceConflict, why
	}
	if a.ETag.Kind == ETagStrong && b.ETag.Kind == ETagStrong {
		return EvidenceStrong, nil
	}
	return EvidenceWeak, nil
}

// HasStrongETag reports whether the fingerprint carries a strong ETag.
func (f Fingerprint) HasStrongETag() bool { return f.ETag.Kind == ETagStrong }
