package probe

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/0then0/rangeprobe/internal/model"
)

func conditionalServer(t *testing.T, mutate func(int, http.ResponseWriter, *http.Request) ([]byte, string)) *httptest.Server {
	t.Helper()
	var n atomic.Int32
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		data, tag := mutate(int(n.Add(1)), w, req)
		if tag != "" {
			w.Header().Set("ETag", tag)
		}
		if data != nil {
			http.ServeContent(w, req, "fixture.bin", time.Time{}, bytes.NewReader(data))
		}
	}))
	t.Cleanup(s.Close)
	return s
}

func runConditional(t *testing.T, s *httptest.Server, mod func(*Options)) *model.Report {
	t.Helper()
	o := opts(s.URL)
	o.IfRange = true
	o.ProbeSize = 8
	if mod != nil {
		mod(&o)
	}
	return Run(t.Context(), o)
}

func TestIfRangeHTTPContracts(t *testing.T) {
	data := []byte("abcdefghijklmnopqrstuvwx")
	for _, tc := range []struct {
		name, behavior, tag string
		code                int
		match, mismatch     string
	}{
		{"correct", "", `"v1"`, 0, "conditional_range_supported", "fallback_observed"},
		{"ignores If-Range", "unconditional", `"v1"`, 1, "conditional_range_supported", "violation"},
		{"ignores Range", "ignore", `"v1"`, 2, "range_ignored", "fallback_observed"},
		{"no ETag", "", "", 3, "unavailable", "unavailable"},
		{"weak ETag", "", `W/"v1"`, 3, "unavailable", "unavailable"},
		{"malformed ETag", "", "v1", 3, "unavailable", "unavailable"},
		{"oversized ETag", "", `"` + strings.Repeat("x", 8001) + `"`, 3, "unavailable", "unavailable"},
		{"long ETag", "", longStrongETag("0001"), 0, "conditional_range_supported", "fallback_observed"},
		{"obs-text ETag", "", "\"caf\xe9\xff\"", 0, "conditional_range_supported", "fallback_observed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var sent []string
			s := conditionalServer(t, func(n int, w http.ResponseWriter, r *http.Request) ([]byte, string) {
				if r.Header.Get("If-Match") != "" {
					t.Error("If-Match sent")
				}
				sent = append(sent, r.Header.Get("If-Range"))
				switch tc.behavior {
				case "unconditional":
					r.Header.Del("If-Range")
				case "ignore":
					r.Header.Del("Range")
				}
				return data, tc.tag
			})
			rep := runConditional(t, s, func(o *Options) { o.Preconditions = true }) // mode itself also suppresses If-Match
			if rep.Summary.ExitCode != tc.code {
				t.Fatalf("summary %+v checks %+v", rep.Summary, rep.Checks)
			}
			if rep.IfRange.ConditionalRanges != tc.match || rep.IfRange.MismatchFallback != tc.mismatch {
				t.Fatal(rep.IfRange)
			}
			if tc.match == "unavailable" {
				if len(sent) != 1 {
					t.Fatal(sent)
				}
				return
			}
			if len(sent) != 3 || sent[0] != "" || sent[1] != tc.tag {
				t.Fatal(sent)
			}
			m := check(t, rep, "if-range-matching")
			raw, err := base64.StdEncoding.DecodeString(m.IfRange.ValidatorBase64)
			if err != nil || string(raw) != tc.tag {
				t.Fatalf("raw validator %q %v", raw, err)
			}
			if sent[2] == sent[1] || !strings.HasPrefix(sent[2], `"rangeprobe-`) {
				t.Fatal(sent)
			}
			fallback := check(t, rep, "if-range-mismatching")
			if tc.behavior != "unconditional" && (fallback.Body == nil || !fallback.Body.Complete || fallback.Body.BytesRead != int64(len(data))) {
				t.Fatal(fallback.Body)
			}
		})
	}
}

func TestIfRangePremiseAndRepresentationChanges(t *testing.T) {
	for _, tc := range []struct {
		name     string
		mutate   func(int, http.ResponseWriter, *http.Request) ([]byte, string)
		code     int
		mismatch string
	}{
		{"replaced", func(n int, w http.ResponseWriter, r *http.Request) ([]byte, string) {
			if n > 1 {
				return []byte("ZYXWVUTSRQPONMLKJIHG"), `"v2"`
			}
			return []byte("abcdefghijklmnopqrstuvwx"), `"v1"`
		}, 3, "fallback_observed"},
		{"missing current ETag", func(n int, w http.ResponseWriter, r *http.Request) ([]byte, string) {
			if n == 3 {
				r.Header.Del("If-Range")
				return []byte("abcdefghijklmnopqrstuvwx"), ""
			}
			return []byte("abcdefghijklmnopqrstuvwx"), `"v1"`
		}, 3, "inconclusive"},
		{"weak current ETag", func(n int, w http.ResponseWriter, r *http.Request) ([]byte, string) {
			if n == 3 {
				r.Header.Del("If-Range")
				return []byte("abcdefghijklmnopqrstuvwx"), `W/"v1"`
			}
			return []byte("abcdefghijklmnopqrstuvwx"), `"v1"`
		}, 3, "inconclusive"},
		{"malformed current ETag", func(n int, w http.ResponseWriter, r *http.Request) ([]byte, string) {
			if n == 3 {
				r.Header.Del("If-Range")
				return []byte("abcdefghijklmnopqrstuvwx"), "broken"
			}
			return []byte("abcdefghijklmnopqrstuvwx"), `"v1"`
		}, 3, "inconclusive"},
		{"random tag now current", func(n int, w http.ResponseWriter, r *http.Request) ([]byte, string) {
			if n == 3 {
				return []byte("abcdefghijklmnopqrstuvwx"), r.Header.Get("If-Range")
			}
			return []byte("abcdefghijklmnopqrstuvwx"), `"v1"`
		}, 3, "inconclusive"},
		{"encoding changed", func(n int, w http.ResponseWriter, r *http.Request) ([]byte, string) {
			if n == 2 {
				w.Header().Set("Content-Encoding", "gzip")
			}
			return []byte("abcdefghijklmnopqrstuvwx"), `"v1"`
		}, 3, "fallback_observed"},
		{"length changed same ETag", func(n int, w http.ResponseWriter, r *http.Request) ([]byte, string) {
			if n == 2 {
				return []byte("123456789012345678901234567890"), `"v1"`
			}
			return []byte("abcdefghijklmnopqrstuvwx"), `"v1"`
		}, 3, "fallback_observed"},
		{"bytes changed same ETag", func(n int, w http.ResponseWriter, r *http.Request) ([]byte, string) {
			if n == 2 {
				return []byte("ZYXWVUTSRQPONMLKJIHGFEDC"), `"v1"`
			}
			return []byte("abcdefghijklmnopqrstuvwx"), `"v1"`
		}, 1, "fallback_observed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rep := runConditional(t, conditionalServer(t, tc.mutate), nil)
			if rep.Summary.ExitCode != tc.code || rep.IfRange.MismatchFallback != tc.mismatch {
				t.Fatalf("%+v %+v checks %+v", rep.Summary, rep.IfRange, rep.Checks)
			}
		})
	}
}

func TestIfRangeWeakConformance(t *testing.T) {
	for _, broken := range []bool{false, true} {
		t.Run(fmt.Sprint(broken), func(t *testing.T) {
			raw := `W/"custom-weak"`
			var weak string
			s := conditionalServer(t, func(n int, w http.ResponseWriter, r *http.Request) ([]byte, string) {
				if n == 2 {
					weak = r.Header.Get("If-Range")
					if broken {
						r.Header.Del("If-Range")
					}
				}
				return []byte("file content"), raw
			})
			rep := runConditional(t, s, func(o *Options) { o.WeakIfRange = true })
			c := check(t, rep, "if-range-weak")
			if weak != raw || !c.IfRange.InvalidClientInput || c.IfRange.Condition != "false" {
				t.Fatalf("%q %+v", weak, c)
			}
			if broken {
				if !hasFinding(c, "IF_RANGE_FALSE_206") || rep.Summary.ExitCode != 1 {
					t.Fatal(c)
				}
			} else if c.IfRange.Outcome != "fallback_observed" || c.Response.Status != 200 {
				t.Fatal(c)
			}
		})
	}
}

type countingBody struct {
	io.ReadCloser
	n      *atomic.Int64
	closed *atomic.Int32
}

func (b *countingBody) Read(p []byte) (int, error) {
	n, e := b.ReadCloser.Read(p)
	b.n.Add(int64(n))
	return n, e
}
func (b *countingBody) Close() error { b.closed.Add(1); return b.ReadCloser.Close() }

type countingTransport struct {
	base   http.RoundTripper
	n      atomic.Int64
	closed atomic.Int32
}

func (c *countingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, e := c.base.RoundTrip(r)
	if e == nil {
		resp.Body = &countingBody{resp.Body, &c.n, &c.closed}
	}
	return resp, e
}

func TestIfRangeFallbackReadIsBoundedAndClosed(t *testing.T) {
	for _, tc := range []struct {
		name                    string
		maxBody, maxBytes, want int64
	}{
		{"total budget", 128, 80, 64},
		{"response budget", 32, 1024, 32},
		{"sanity prefix", 1 << 20, 2 << 20, 64 << 10},
	} {
		t.Run(tc.name, func(t *testing.T) {
			disconnected := make(chan struct{})
			var n atomic.Int32
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("ETag", `"v1"`)
				if n.Add(1) < 3 {
					w.Header().Set("Content-Range", "bytes 0-7/1073741824")
					w.WriteHeader(206)
					w.Write([]byte("abcdefgh"))
					return
				}
				w.Header().Set("Content-Length", "1073741824")
				w.WriteHeader(200)
				for {
					select {
					case <-r.Context().Done():
						close(disconnected)
						return
					default:
					}
					if _, err := w.Write(bytes.Repeat([]byte("x"), 1024)); err != nil {
						close(disconnected)
						return
					}
					w.(http.Flusher).Flush()
				}
			}))
			defer s.Close()
			tr := http.DefaultTransport.(*http.Transport).Clone()
			tr.DisableKeepAlives = true
			defer tr.CloseIdleConnections()
			ct := &countingTransport{base: tr}
			rep := runConditional(t, s, func(o *Options) {
				o.RoundTripper = ct
				o.Budgets.MaxBody = tc.maxBody
				o.Budgets.MaxBytes = tc.maxBytes
			})
			c := check(t, rep, "if-range-mismatching")
			if ct.n.Load() != tc.want+16 || ct.closed.Load() != 3 || rep.Budget.BytesRead != tc.want+16 || c.Body.BytesRead != tc.want {
				t.Fatalf("read %d closed %d budget %+v body %+v", ct.n.Load(), ct.closed.Load(), rep.Budget, c.Body)
			}
			if c.Body.Complete || c.Body.EndState != "prefix" || hasFinding(c, "BODY_TRUNCATED") || c.IfRange.Outcome != "fallback_observed" {
				t.Fatal(c)
			}
			select {
			case <-disconnected:
			case <-time.After(2 * time.Second):
				t.Fatal("server did not observe closed response")
			}

		})
	}
}

func TestIfRangeFailuresAndBudgets(t *testing.T) {
	for _, tc := range []struct {
		name       string
		status     int
		sleep      bool
		disconnect bool
	}{
		{name: "412", status: 412}, {name: "416", status: 416}, {name: "redirect", status: 302}, {name: "timeout", sleep: true}, {name: "transport", disconnect: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := conditionalServer(t, func(n int, w http.ResponseWriter, r *http.Request) ([]byte, string) {
				if n == 3 {
					if tc.sleep {
						<-r.Context().Done()
						return nil, ""
					}
					if tc.disconnect {
						conn, _, _ := w.(http.Hijacker).Hijack()
						conn.Close()
						return nil, ""
					}
					if tc.status == 302 {
						w.Header().Set("Location", "/loop")
					}
					w.WriteHeader(tc.status)
					return nil, ""
				}
				return []byte("abcdefghijklmnopqrstuvwx"), `"v1"`
			})
			rep := runConditional(t, s, func(o *Options) { o.Budgets.RequestTimeout = 50 * time.Millisecond; o.Budgets.MaxRedirects = 0 })
			c := check(t, rep, "if-range-mismatching")
			if rep.Summary.ExitCode != 3 || c.IfRange.Outcome == "fallback_observed" || c.Status == model.KindViolation {
				t.Fatalf("%+v %+v", rep.Summary, c)
			}
			if tc.status == 412 || tc.status == 416 {
				if c.Response.Status != tc.status {
					t.Fatal(c.Response)
				}
			}
		})
	}
	s := conditionalServer(t, func(n int, w http.ResponseWriter, r *http.Request) ([]byte, string) {
		return []byte("abcdefghijklmnopqrstuvwx"), `"v1"`
	})
	for _, mod := range []func(*Options){func(o *Options) { o.Budgets.MaxRequests = 1 }, func(o *Options) { o.Budgets.MaxBytes = 8 }, func(o *Options) { o.Budgets.RunTimeout = time.Nanosecond }} {
		r := runConditional(t, s, mod)
		if r.Summary.ExitCode != 3 {
			t.Fatal(r.Summary)
		}
	}
}

func TestIfRangeRedirectForwarding(t *testing.T) {
	for _, cross := range []bool{false, true} {
		t.Run(fmt.Sprint(cross), func(t *testing.T) {
			var forwarded []http.Header
			target := conditionalServer(t, func(n int, w http.ResponseWriter, r *http.Request) ([]byte, string) {
				forwarded = append(forwarded, r.Header.Clone())
				return []byte("abcdefghijklmnopqrstuvwx"), `"v1"`
			})
			var origin *httptest.Server
			origin = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/data" && !cross {
					forwarded = append(forwarded, r.Header.Clone())
					w.Header().Set("ETag", `"v1"`)
					http.ServeContent(w, r, "fixture", time.Time{}, strings.NewReader("abcdefghijklmnopqrstuvwx"))
					return
				}
				dest := target.URL
				if !cross {
					dest = origin.URL + "/data"
				}
				http.Redirect(w, r, dest, 302)
			}))
			defer origin.Close()
			rep := runConditional(t, origin, func(o *Options) { o.Headers = http.Header{"Authorization": {"secret"}, "X-Key": {"private"}} })
			for i, h := range forwarded {
				if cross {
					if h.Get("Authorization") != "" || h.Get("X-Key") != "" || h.Get("If-Range") != "" {
						t.Fatal(h)
					}
				} else if h.Get("Authorization") != "secret" || (i > 0 && h.Get("If-Range") == "") {
					t.Fatal(h)
				}
			}
			if cross {
				if rep.Summary.ExitCode != 3 || check(t, rep, "if-range-mismatching").IfRange.ValidatorSent {
					t.Fatal(rep.Summary)
				}
			} else if rep.Summary.ExitCode != 0 {
				t.Fatalf("%+v %+v", rep.Summary, rep.Checks)
			}
		})
	}
}

func TestIfRangeRedirectChangesResourceWithSameETag(t *testing.T) {
	var calls atomic.Int32
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			dest := "/one"
			if calls.Add(1) > 1 {
				dest = "/two"
			}
			http.Redirect(w, r, dest, 302)
			return
		}
		data := "abcdefghijkl"
		if r.URL.Path == "/two" {
			data = "ZYXWVUTSRQPO"
		}
		w.Header().Set("ETag", `"v1"`)
		http.ServeContent(w, r, "fixture", time.Time{}, strings.NewReader(data))
	}))
	defer s.Close()
	o := opts(s.URL + "/start")
	o.IfRange = true
	o.ProbeSize = 5
	rep := Run(t.Context(), o)
	c := check(t, rep, "if-range-matching")
	if rep.Summary.ExitCode != 3 || hasFinding(c, "REREAD_INCONSISTENT") || !hasFinding(c, "IF_RANGE_RESOURCE_CHANGED") {
		t.Fatalf("%+v %+v", rep.Summary, c)
	}
	if check(t, rep, "if-range-mismatching").IfRange.Outcome != "fallback_observed" {
		t.Fatal(rep.IfRange)
	}
}

func TestIfRangeFallbackBodyTimeout(t *testing.T) {
	var n atomic.Int32
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"v1"`)
		if n.Add(1) < 3 {
			w.Header().Set("Content-Range", "bytes 0-7/24")
			w.WriteHeader(206)
			w.Write([]byte("abcdefgh"))
			return
		}
		w.Header().Set("Content-Length", "24")
		w.WriteHeader(200)
		w.Write([]byte("abc"))
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer s.Close()
	rep := runConditional(t, s, func(o *Options) { o.Budgets.RequestTimeout = 50 * time.Millisecond })
	c := check(t, rep, "if-range-mismatching")
	if rep.Summary.ExitCode != 3 || c.IfRange.Outcome != "fallback_observed" || !hasFinding(c, "REQUEST_TIMEOUT") || c.Body.Complete || c.Body.EndState != "error" || c.Body.BytesRead != 3 {
		t.Fatalf("%+v %+v", rep.Summary, c)
	}
}
