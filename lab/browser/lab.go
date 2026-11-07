package main

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/0then0/rangeprobe/internal/testsrv"
)

// config describes one lab: where the two origins are and what they serve.
type config struct {
	PageOrigin string        // the origin of the page, as the browser writes it
	DataOrigin string        // the origin of the file server
	WebDir     string        // the static page
	Size       int           // length of the reference file
	LargeSize  int64         // length of the full response that ignores Range at length
	Slow       time.Duration // how long the slow routes stall
}

// corsPolicy says what a route lets a page on PageOrigin do.
type corsPolicy struct {
	allow  bool
	expose []string
}

var exposeAll = []string{"Content-Range", "Accept-Ranges", "ETag", "Content-Length", "Content-Encoding"}

type route struct {
	name string
	what string
	cors corsPolicy
	h    http.Handler
}

// stats counts what the file server saw, so a test can tell from outside the
// browser what the browser did.
type stats struct {
	mu     sync.Mutex
	routes map[string]*routeStats
}

type routeStats struct {
	Requests     int      `json:"requests"`
	Preflights   int      `json:"preflights"`
	LastRange    string   `json:"last_range"`
	LastOrigin   string   `json:"last_origin"`
	Ranges       []string `json:"ranges"`
	BytesWritten int64    `json:"bytes_written,omitempty"`
	Aborted      int      `json:"aborted,omitempty"`
	Completed    int      `json:"completed,omitempty"`
}

func (s *stats) with(name string, f func(*routeStats)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.routes == nil {
		s.routes = map[string]*routeStats{}
	}
	r := s.routes[name]
	if r == nil {
		r = &routeStats{Ranges: []string{}}
		s.routes[name] = r
	}
	f(r)
}

func (s *stats) reset() {
	s.mu.Lock()
	s.routes = nil
	s.mu.Unlock()
}

func (s *stats) json() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, _ := json.MarshalIndent(map[string]any{"routes": s.routes}, "", "  ")
	return append(b, '\n')
}

// lab holds the two handlers of the stand.
type lab struct {
	cfg    config
	data   []byte
	stats  *stats
	routes []route
}

func gzipped(b []byte) []byte {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	w.Write(b)
	w.Close()
	return buf.Bytes()
}

func newLab(cfg config) *lab {
	l := &lab{cfg: cfg, data: testsrv.Content(cfg.Size), stats: &stats{}}
	base := func(tamper func(*testsrv.Reply)) http.Handler {
		return &testsrv.Handler{Data: l.data, ETag: `"lab-v1"`, LastModified: "Sat, 01 Nov 2025 10:00:00 GMT", Tamper: tamper}
	}
	// shift serves every 206 from one byte further on: right length and
	// headers, wrong bytes.
	shift := func(r *testsrv.Reply) {
		if r.Status != http.StatusPartialContent {
			return
		}
		out := make([]byte, len(r.Body))
		for i := range out {
			out[i] = l.data[(int(r.Start)+i+1)%len(l.data)]
		}
		r.Body = out
	}
	ignore := func(r *testsrv.Reply) {
		r.Status = http.StatusOK
		r.Header.Del("Content-Range")
		r.Body = l.data
	}
	// encodeFull ignores Range and sends the whole file gzip-encoded, as a
	// compressing server that does not support ranges would. Chrome sends no
	// Accept-Encoding on a range request and rejects the unrequested coding.
	gzFull := gzipped(l.data)
	encodeFull := func(r *testsrv.Reply) {
		ignore(r)
		r.Header.Set("Content-Encoding", "gzip")
		r.Body = gzFull
	}
	hiddenExpose := []string{"Accept-Ranges", "ETag"} // everything but Content-Range
	l.routes = []route{
		{"ok", "correct bytes, every header readable", corsPolicy{true, exposeAll}, base(nil)},
		{"hidden-content-range", "correct bytes, Content-Range not exposed", corsPolicy{true, hiddenExpose}, base(nil)},
		{"no-cors", "correct bytes, no CORS headers: the browser hides the response", corsPolicy{}, base(nil)},
		{"wrong-bytes", "correct headers, bytes shifted by one", corsPolicy{true, exposeAll}, base(shift)},
		{"range-ignored", "200 with the whole file for every range", corsPolicy{true, exposeAll}, base(ignore)},
		{"range-ignored-large", fmt.Sprintf("200 with %d bytes, paced, for every range", cfg.LargeSize), corsPolicy{true, exposeAll}, l.large()},
		{"slow-headers", fmt.Sprintf("headers stall for %s", cfg.Slow), corsPolicy{true, exposeAll}, base(func(r *testsrv.Reply) { r.Delay = cfg.Slow })},
		{"slow-body", fmt.Sprintf("headers and half the body at once, the rest after %s", cfg.Slow), corsPolicy{true, exposeAll}, base(func(r *testsrv.Reply) { r.BodyDelay = cfg.Slow })},
		{"encoded", "200 with the whole file gzip-encoded; Chrome sent no Accept-Encoding and rejects the fetch", corsPolicy{true, exposeAll}, base(encodeFull)},
	}
	return l
}

// large streams a full 200 of LargeSize bytes made of repeats of the
// reference, a block every few milliseconds, and records how far it got.
func (l *lab) large() http.Handler {
	const block = 64 << 10
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Accept-Ranges", "bytes")
		w.Header().Set("Content-Length", fmt.Sprint(l.cfg.LargeSize))
		w.WriteHeader(http.StatusOK)
		fl, _ := w.(http.Flusher)
		var sent int64
		for sent < l.cfg.LargeSize {
			n := int64(block)
			if rest := l.cfg.LargeSize - sent; rest < n {
				n = rest
			}
			// The same bytes as the reference at offset sent mod its length.
			chunk := make([]byte, n)
			for i := range chunk {
				chunk[i] = l.data[(sent+int64(i))%int64(len(l.data))]
			}
			m, err := w.Write(chunk)
			sent += int64(m)
			l.stats.with("range-ignored-large", func(s *routeStats) { s.BytesWritten += int64(m) })
			if err != nil || r.Context().Err() != nil {
				l.stats.with("range-ignored-large", func(s *routeStats) { s.Aborted++ })
				return
			}
			if fl != nil {
				fl.Flush()
			}
			select {
			case <-time.After(2 * time.Millisecond):
			case <-r.Context().Done():
				l.stats.with("range-ignored-large", func(s *routeStats) { s.Aborted++ })
				return
			}
		}
		l.stats.with("range-ignored-large", func(s *routeStats) { s.Completed++ })
	})
}

// withCORS applies a route's policy and answers preflights. When the policy
// denies the page, no CORS header is sent at all.
func (l *lab) withCORS(rt route, cors bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		l.stats.with(rt.name, func(s *routeStats) {
			s.LastOrigin = origin
			if r.Method == http.MethodOptions {
				s.Preflights++
				return
			}
			s.Requests++
			s.LastRange = r.Header.Get("Range")
			if r.Header.Get("Range") != "" {
				s.Ranges = append(s.Ranges, r.Header.Get("Range"))
			}
		})
		allowed := cors && rt.cors.allow && origin == l.cfg.PageOrigin
		if allowed {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Add("Vary", "Origin")
		}
		if r.Method == http.MethodOptions {
			if allowed {
				w.Header().Set("Access-Control-Allow-Methods", "GET")
				w.Header().Set("Access-Control-Allow-Headers", "Range")
				w.Header().Set("Access-Control-Max-Age", "1")
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if allowed && len(rt.cors.expose) > 0 {
			w.Header().Set("Access-Control-Expose-Headers", strings.Join(rt.cors.expose, ", "))
		}
		rt.h.ServeHTTP(w, r)
	})
}

func (l *lab) index() string {
	var b strings.Builder
	fmt.Fprintf(&b, "RangeProbe browser lab\n\npage origin:  %s\ndata origin:  %s\nreference:    %s/reference.bin (%d bytes)\n\nroutes on the data origin (cross-origin for the page):\n\n", l.cfg.PageOrigin, l.cfg.DataOrigin, l.cfg.PageOrigin, l.cfg.Size)
	for _, rt := range l.routes {
		fmt.Fprintf(&b, "  %s/%s\n      %s\n", l.cfg.DataOrigin, rt.name, rt.what)
	}
	fmt.Fprintf(&b, "\nthe same routes without CORS on the page origin (same-origin): %s/data/<route>\nserver-side counters: %s/__stats  (reset: %s/__reset)\n", l.cfg.PageOrigin, l.cfg.DataOrigin, l.cfg.DataOrigin)
	return b.String()
}

// dataHandler is the file server: every route with its CORS policy.
func (l *lab) dataHandler() http.Handler {
	mux := http.NewServeMux()
	for _, rt := range l.routes {
		mux.Handle("/"+rt.name, l.withCORS(rt, true))
	}
	mux.HandleFunc("/__stats", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(l.stats.json())
	})
	mux.HandleFunc("/__reset", func(w http.ResponseWriter, r *http.Request) {
		l.stats.reset()
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprint(w, l.index())
	})
	return mux
}

// pageHandler serves the static page, the reference file and, for the
// same-origin case, the routes without CORS under /data/.
func (l *lab) pageHandler() http.Handler {
	mux := http.NewServeMux()
	names := make([]string, 0, len(l.routes))
	for _, rt := range l.routes {
		names = append(names, rt.name)
		mux.Handle("/data/"+rt.name, l.withCORS(rt, false))
	}
	sort.Strings(names)
	mux.HandleFunc("/reference.bin", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", `attachment; filename="reference.bin"`)
		w.Write(l.data)
	})
	static := http.FileServer(http.Dir(l.cfg.WebDir))
	mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		static.ServeHTTP(w, r)
	}))
	return mux
}
