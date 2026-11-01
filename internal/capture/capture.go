// Package capture implements the streaming sink that receives a response
// body: it hashes the bytes, optionally retains a bounded copy, and compares
// them against a reference slice without loading the reference into memory.
package capture

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
)

// Reference is the minimal view of the local reference file.
type Reference interface {
	ReadAt(p []byte, off int64) (int, error)
	Size() int64
}

// Config configures a Sink.
type Config struct {
	// Start is the representation offset of the first body byte.
	Start int64
	// Ref enables comparison when non-nil.
	Ref Reference
	// Retain keeps up to RetainMax body bytes in memory.
	Retain    bool
	RetainMax int
	// Dump is the maximum number of bytes to capture around the first
	// mismatch (0 disables).
	Dump int
}

// Sink is an io.Writer. It is not safe for concurrent use.
type Sink struct {
	cfg  Config
	obs  hash.Hash
	exp  hash.Hash
	n    int64
	buf  []byte
	win  []byte
	refE error

	first    int64
	mismatch int64
	beyond   int64
	compared int64

	// shift[0] tests the body against reference offset-1, shift[1] offset+1.
	shift [2]shiftState
	frag  *Fragment
}

type shiftState struct {
	bad     int64
	invalid bool
}

// Fragment holds hex-encoded bytes around the first mismatch.
type Fragment struct {
	Offset   int64
	Expected string
	Observed string
}

// New returns a Sink.
func New(cfg Config) *Sink {
	return &Sink{cfg: cfg, obs: sha256.New(), exp: sha256.New(), first: -1}
}

// Write implements io.Writer.
func (s *Sink) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	s.obs.Write(p)
	if s.cfg.Retain && len(s.buf) < s.cfg.RetainMax {
		room := s.cfg.RetainMax - len(s.buf)
		s.buf = append(s.buf, p[:min(room, len(p))]...)
	}
	if s.cfg.Ref != nil {
		s.compare(p)
	}
	s.n += int64(len(p))
	return len(p), nil
}

func (s *Sink) compare(p []byte) {
	abs := s.cfg.Start + s.n
	size := s.cfg.Ref.Size()
	// One window read covers offsets abs-1 .. abs+len(p) (inclusive).
	lo := max(abs-1, 0)
	hi := min(abs+int64(len(p))+1, size)
	var window []byte
	if hi > lo {
		if int64(cap(s.win)) < hi-lo {
			s.win = make([]byte, hi-lo)
		}
		window = s.win[:hi-lo]
		n, err := s.cfg.Ref.ReadAt(window, lo)
		if n < len(window) {
			s.refE = fmt.Errorf("reference read: %w", errOrShort(err))
			window = window[:n]
		}
	}
	at := func(idx int64) (byte, bool) {
		j := idx - lo
		if idx < 0 || j < 0 || j >= int64(len(window)) {
			return 0, false
		}
		return window[j], true
	}
	for i, b := range p {
		idx := abs + int64(i)
		e, ok := at(idx)
		if ok {
			s.compared++
			s.exp.Write([]byte{e})
			if e != b {
				s.noteMismatch(idx, p, i)
			}
		} else {
			s.beyond++
			s.noteMismatch(idx, p, i)
		}
		for k, d := range [2]int64{-1, 1} {
			st := &s.shift[k]
			if st.invalid {
				continue
			}
			c, ok := at(idx + d)
			if !ok {
				st.invalid = true
				continue
			}
			if c != b {
				st.bad++
			}
		}
	}
}

func errOrShort(err error) error {
	if err != nil {
		return err
	}
	return fmt.Errorf("short read")
}

func (s *Sink) noteMismatch(idx int64, p []byte, i int) {
	s.mismatch++
	if s.first >= 0 {
		return
	}
	s.first = idx
	if s.cfg.Dump > 0 {
		end := min(i+s.cfg.Dump, len(p))
		eb := make([]byte, end-i)
		n, _ := s.cfg.Ref.ReadAt(eb, idx)
		s.frag = &Fragment{Offset: idx, Expected: hex.EncodeToString(eb[:max(n, 0)]), Observed: hex.EncodeToString(p[i:end])}
	}
}

// N returns the number of body bytes received.
func (s *Sink) N() int64 { return s.n }

// SHA256 returns the hex digest of the received bytes.
func (s *Sink) SHA256() string { return hex.EncodeToString(s.obs.Sum(nil)) }

// ExpectedSHA256 returns the digest of the reference bytes that overlapped
// the received bytes (empty without a reference).
func (s *Sink) ExpectedSHA256() string {
	if s.cfg.Ref == nil {
		return ""
	}
	return hex.EncodeToString(s.exp.Sum(nil))
}

// Bytes returns the retained prefix of the body.
func (s *Sink) Bytes() []byte { return s.buf }

// Comparing reports whether a reference is attached.
func (s *Sink) Comparing() bool { return s.cfg.Ref != nil }

// Result summarises the comparison.
type Result struct {
	Compared        int64
	FirstMismatch   int64 // -1 when none
	MismatchCount   int64
	BeyondReference int64
	ShiftHint       string
	Fragment        *Fragment
	RefErr          error
}

// Result returns the comparison state.
func (s *Sink) Result() Result {
	r := Result{
		Compared: s.compared, FirstMismatch: s.first, MismatchCount: s.mismatch,
		BeyondReference: s.beyond, Fragment: s.frag, RefErr: s.refE,
	}
	if s.mismatch > 0 && s.n > 0 {
		for k, name := range [2]string{"one byte earlier in the reference (offset-1)", "one byte later in the reference (offset+1)"} {
			if !s.shift[k].invalid && s.shift[k].bad == 0 {
				r.ShiftHint = "body equals the reference slice shifted to " + name
			}
		}
	}
	return r
}
