// Package testsrv is a small, RFC-conforming single-range HTTP handler used
// by tests. Tests alter individual replies through Tamper to model defects.
// It is test support, not a general HTTP testing framework.
package testsrv

import (
	"fmt"
	"math/rand/v2"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Content returns n pseudo-random bytes. The sequence is deterministic and
// differs at every offset, so shifted or misplaced slices are detectable.
func Content(n int) []byte {
	r := rand.New(rand.NewPCG(0x52616e67, 0x6550726f))
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(r.Uint32())
	}
	return b
}

// Reply is the response a Handler is about to send. Tamper may modify it.
type Reply struct {
	Status int
	Header http.Header
	Body   []byte

	// Req is the incoming request; Range is its Range header.
	Req   *http.Request
	Range string

	// Start and End are the inclusive interval served when the reply is a
	// correct 206; Start is -1 otherwise.
	Start, End int64

	// NoContentLength sends the body chunked, without Content-Length.
	NoContentLength bool
	// CutAfter, when >= 0, aborts the connection after that many body bytes
	// although headers announced the whole body.
	CutAfter int
	// Delay is applied before headers are written; BodyDelay between the
	// first half of the body and the second.
	Delay, BodyDelay time.Duration
}

// Logged is a record of one received request.
type Logged struct {
	Range  string
	Header http.Header
}

// Handler serves Data with correct range semantics.
type Handler struct {
	Data         []byte
	ETag         string // raw header value, e.g. `"v1"` or `W/"v1"`; empty omits
	LastModified string
	// AcceptRanges is sent verbatim when non-empty ("bytes" by default
	// when Data is served with ranges; set to "-" to omit the header).
	AcceptRanges string
	ContentType  string
	Tamper       func(*Reply)

	mu  sync.Mutex
	log []Logged
}

// Requests returns a copy of the request log.
func (h *Handler) Requests() []Logged {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]Logged(nil), h.log...)
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	h.log = append(h.log, Logged{Range: r.Header.Get("Range"), Header: r.Header.Clone()})
	h.mu.Unlock()

	rep := &Reply{Status: 200, Header: http.Header{}, Req: r, Range: r.Header.Get("Range"), Start: -1, CutAfter: -1}
	size := int64(len(h.Data))
	if h.ETag != "" {
		rep.Header.Set("ETag", h.ETag)
	}
	if h.LastModified != "" {
		rep.Header.Set("Last-Modified", h.LastModified)
	}
	switch h.AcceptRanges {
	case "":
		rep.Header.Set("Accept-Ranges", "bytes")
	case "-":
	default:
		rep.Header.Set("Accept-Ranges", h.AcceptRanges)
	}
	ct := h.ContentType
	if ct == "" {
		ct = "application/octet-stream"
	}
	rep.Header.Set("Content-Type", ct)
	rep.Body = h.Data

	if spec := rep.Range; spec != "" {
		first, last, ok, valid := parseRange(spec, size)
		switch {
		case !valid:
		case !ok:
			rep.Status = http.StatusRequestedRangeNotSatisfiable
			rep.Header.Set("Content-Range", fmt.Sprintf("bytes */%d", size))
			rep.Body = nil
		default:
			rep.Status = http.StatusPartialContent
			rep.Header.Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", first, last, size))
			rep.Body = h.Data[first : last+1]
			rep.Start, rep.End = first, last
		}
	}
	if h.Tamper != nil {
		h.Tamper(rep)
	}
	time.Sleep(rep.Delay)
	for k, v := range rep.Header {
		w.Header()[k] = v
	}
	if !rep.NoContentLength {
		w.Header().Set("Content-Length", strconv.Itoa(len(rep.Body)))
	}
	w.WriteHeader(rep.Status)
	body := rep.Body
	if rep.CutAfter >= 0 && rep.CutAfter < len(body) {
		body = body[:rep.CutAfter]
	}
	fl, _ := w.(http.Flusher)
	half := len(body) / 2
	w.Write(body[:half])
	if fl != nil {
		fl.Flush()
	}
	time.Sleep(rep.BodyDelay)
	w.Write(body[half:])
	if rep.CutAfter >= 0 && rep.CutAfter < len(rep.Body) {
		if fl != nil {
			fl.Flush()
		}
		panic(http.ErrAbortHandler)
	}
}

// parseRange handles one "bytes=a-b", "bytes=a-" or "bytes=-n" spec.
// valid is false for anything else (the caller then ignores Range).
func parseRange(spec string, size int64) (first, last int64, ok, valid bool) {
	rest, found := strings.CutPrefix(spec, "bytes=")
	if !found || strings.Contains(rest, ",") {
		return 0, 0, false, false
	}
	a, b, found := strings.Cut(rest, "-")
	if !found {
		return 0, 0, false, false
	}
	switch {
	case a == "":
		n, err := strconv.ParseInt(b, 10, 64)
		if err != nil || n <= 0 {
			return 0, 0, false, false
		}
		if size == 0 {
			return 0, 0, false, true
		}
		return max(0, size-n), size - 1, true, true
	default:
		f, err := strconv.ParseInt(a, 10, 64)
		if err != nil {
			return 0, 0, false, false
		}
		l := size - 1
		if b != "" {
			v, err := strconv.ParseInt(b, 10, 64)
			if err != nil || v < f {
				return 0, 0, false, false
			}
			l = min(v, size-1)
		}
		if f >= size {
			return 0, 0, false, true
		}
		return f, l, true, true
	}
}
