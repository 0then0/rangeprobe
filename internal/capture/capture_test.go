package capture

import (
	"bytes"
	"testing"
)

type memRef []byte

func (m memRef) Size() int64 { return int64(len(m)) }
func (m memRef) ReadAt(p []byte, off int64) (int, error) {
	if off >= int64(len(m)) {
		return 0, nil
	}
	return copy(p, m[off:]), nil
}

func pattern(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte((i*7 + i/251 + i*i/13) % 256)
	}
	return b
}

func feed(s *Sink, b []byte, chunk int) {
	for len(b) > 0 {
		n := min(chunk, len(b))
		s.Write(b[:n])
		b = b[n:]
	}
}

func TestMatchAcrossChunks(t *testing.T) {
	ref := memRef(pattern(10000))
	s := New(Config{Start: 1234, Ref: ref})
	feed(s, ref[1234:5234], 97)
	r := s.Result()
	if r.FirstMismatch != -1 || r.MismatchCount != 0 || r.Compared != 4000 {
		t.Fatalf("unexpected result %+v", r)
	}
	if s.SHA256() != s.ExpectedSHA256() {
		t.Error("digests of equal data differ")
	}
}

func TestMismatchAtOffset(t *testing.T) {
	ref := memRef(pattern(5000))
	body := bytes.Clone(ref[100:600])
	body[333] ^= 0xFF
	s := New(Config{Start: 100, Ref: ref, Dump: 4})
	feed(s, body, 64)
	r := s.Result()
	if r.FirstMismatch != 433 || r.MismatchCount != 1 {
		t.Fatalf("got %+v", r)
	}
	if r.Fragment == nil || r.Fragment.Offset != 433 || len(r.Fragment.Observed) == 0 {
		t.Fatalf("fragment %+v", r.Fragment)
	}
	if r.ShiftHint != "" {
		t.Errorf("unexpected shift hint %q", r.ShiftHint)
	}
}

func TestOneByteShiftDetected(t *testing.T) {
	ref := memRef(pattern(5000))
	for _, d := range []int{-1, 1} {
		start := 1000
		body := bytes.Clone(ref[start+d : start+d+512])
		s := New(Config{Start: int64(start), Ref: ref})
		feed(s, body, 100)
		r := s.Result()
		if r.MismatchCount == 0 {
			t.Fatalf("d=%d: shifted body compared equal; pattern too regular", d)
		}
		if r.ShiftHint == "" {
			t.Errorf("d=%d: shift not detected", d)
		}
	}
}

func TestBytesBeyondReference(t *testing.T) {
	ref := memRef(pattern(100))
	s := New(Config{Start: 90, Ref: ref})
	feed(s, append(bytes.Clone(ref[90:]), 1, 2, 3), 7)
	r := s.Result()
	if r.BeyondReference != 3 || r.FirstMismatch != 100 || r.Compared != 10 {
		t.Fatalf("got %+v", r)
	}
}

func TestRetainBounded(t *testing.T) {
	s := New(Config{Retain: true, RetainMax: 10})
	feed(s, pattern(100), 30)
	if len(s.Bytes()) != 10 || s.N() != 100 {
		t.Fatalf("retained %d, n %d", len(s.Bytes()), s.N())
	}
}

func TestNoReferenceStillHashes(t *testing.T) {
	s := New(Config{})
	s.Write([]byte("abc"))
	if s.SHA256() != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
		t.Errorf("sha256 %s", s.SHA256())
	}
	if s.ExpectedSHA256() != "" || s.Comparing() {
		t.Error("no reference attached")
	}
}
