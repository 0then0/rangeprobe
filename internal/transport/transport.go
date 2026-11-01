// Package transport performs single GET probes over net/http under hard
// limits: bounded redirects, a credential-safe redirect policy, per-request
// timeouts and bounded body reads. It records what happened and draws no
// conclusions about correctness.
package transport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/0then0/rangeprobe/internal/redact"
	"github.com/0then0/rangeprobe/internal/version"
)

// FailKind classifies request-level and body-level failures.
type FailKind string

// Failure kinds.
const (
	FailTimeout         FailKind = "timeout"
	FailRunTimeout      FailKind = "run_timeout"
	FailCancelled       FailKind = "cancelled"
	FailRedirectRefused FailKind = "redirect_refused"
	FailRedirectLimit   FailKind = "redirect_limit"
	FailTLS             FailKind = "tls"
	FailNetwork         FailKind = "network"
	// FailTruncated means the stream ended before the declared framing
	// completed (io.ErrUnexpectedEOF).
	FailTruncated FailKind = "truncated"
)

// Failure describes why a request or body read did not complete. Message is
// already redacted.
type Failure struct {
	Kind    FailKind
	Message string
}

// Config configures a Client.
type Config struct {
	// Headers are user-supplied request headers. They are sent only to the
	// origin of the initial URL and dropped on cross-origin redirects.
	Headers        http.Header
	RequestTimeout time.Duration
	MaxRedirects   int
	// RootCAs extends certificate verification; nil uses the system pool.
	// Verification is never disabled.
	RootCAs *x509.CertPool
	// RoundTripper replaces the network transport (tests only).
	RoundTripper http.RoundTripper
	Redactor     *redact.Redactor
}

// Client issues probe requests. It is safe for sequential use.
type Client struct {
	cfg Config
	hc  *http.Client
}

// New returns a Client.
func New(cfg Config) *Client {
	if cfg.Redactor == nil {
		cfg.Redactor = redact.New(true)
	}
	var rt http.RoundTripper = cfg.RoundTripper
	if rt == nil {
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.DisableCompression = true // never decode: range offsets address encoded bytes
		tr.DisableKeepAlives = true  // each probe is independent; no poisoned reuse
		tr.TLSClientConfig = &tls.Config{RootCAs: cfg.RootCAs, MinVersion: tls.VersionTLS12}
		tr.ForceAttemptHTTP2 = true
		rt = tr
	}
	c := &Client{cfg: cfg}
	c.hc = &http.Client{Transport: rt, CheckRedirect: c.checkRedirect}
	return c
}

// Request describes one probe.
type Request struct {
	URL     string
	Range   string // Range header value; empty sends none
	IfMatch string // If-Match header value; empty sends none
}

// Head is the response status line and headers.
type Head struct {
	Status        int
	Proto         string
	Header        http.Header
	ContentLength int64 // -1 when unknown
	Chunked       bool
}

// BodyPlan tells Fetch how to consume a body.
type BodyPlan struct {
	// Limit is the maximum number of octets to read; 0 reads nothing.
	Limit int64
	Sink  io.Writer
}

// Hop is one followed redirect.
type Hop struct {
	Status int
	From   string
	To     string
}

// Exchange is the recorded result of one probe. URLs are raw (unredacted)
// and must be redacted before leaving the process.
type Exchange struct {
	Req      Request
	Head     *Head
	FinalURL string
	Hops     []Hop

	// Body read results. EOF is true when the end of the body was seen.
	Read     int64
	EOF      bool
	Limit    int64
	BodyFail *Failure

	// Fail is set when no response was obtained.
	Fail     *Failure
	Duration time.Duration
}

type fetchState struct {
	origin *url.URL
	hops   []Hop
	policy *Failure
}

type stateKey struct{}

// Fetch sends one GET. decide is called once with the response head and
// returns how much of the body to read. The body is always closed.
func (c *Client) Fetch(ctx context.Context, req Request, decide func(*Head) BodyPlan) *Exchange {
	start := time.Now()
	ex := &Exchange{Req: req}
	defer func() { ex.Duration = time.Since(start) }()

	u, err := url.Parse(req.URL)
	if err != nil {
		ex.Fail = &Failure{FailNetwork, c.cfg.Redactor.Text(err.Error())}
		return ex
	}
	st := &fetchState{origin: u}
	rctx, cancel := context.WithTimeout(context.WithValue(ctx, stateKey{}, st), c.cfg.RequestTimeout)
	defer cancel()

	hreq, err := http.NewRequestWithContext(rctx, http.MethodGet, req.URL, nil)
	if err != nil {
		ex.Fail = &Failure{FailNetwork, c.cfg.Redactor.Text(err.Error())}
		return ex
	}
	for name, vals := range c.cfg.Headers {
		for _, v := range vals {
			hreq.Header.Add(name, v)
		}
	}
	hreq.Header.Set("User-Agent", version.UserAgent())
	hreq.Header.Set("Accept", "*/*")
	hreq.Header.Set("Accept-Encoding", "identity")
	if req.Range != "" {
		hreq.Header.Set("Range", req.Range)
	}
	if req.IfMatch != "" {
		hreq.Header.Set("If-Match", req.IfMatch)
	}

	resp, err := c.hc.Do(hreq)
	ex.Hops = st.hops
	if err != nil {
		ex.Fail = c.classify(ctx, rctx, st, err)
		return ex
	}
	defer resp.Body.Close()
	ex.FinalURL = resp.Request.URL.String()
	head := &Head{
		Status: resp.StatusCode, Proto: resp.Proto, Header: resp.Header,
		ContentLength: resp.ContentLength,
	}
	for _, te := range resp.TransferEncoding {
		if strings.EqualFold(te, "chunked") {
			head.Chunked = true
		}
	}
	ex.Head = head

	plan := decide(head)
	ex.Limit = plan.Limit
	if plan.Limit <= 0 {
		return ex
	}
	buf := make([]byte, 32<<10)
	for ex.Read < plan.Limit {
		n := int(min(int64(len(buf)), plan.Limit-ex.Read))
		m, rerr := resp.Body.Read(buf[:n])
		if m > 0 {
			if plan.Sink != nil {
				plan.Sink.Write(buf[:m])
			}
			ex.Read += int64(m)
		}
		if rerr == io.EOF {
			ex.EOF = true
			break
		}
		if rerr != nil {
			ex.BodyFail = c.classify(ctx, rctx, st, rerr)
			break
		}
	}
	return ex
}

// classify maps an error to a Failure, preferring run-level causes.
func (c *Client) classify(run, req context.Context, st *fetchState, err error) *Failure {
	msg := c.cfg.Redactor.Text(err.Error())
	switch {
	case errors.Is(run.Err(), context.Canceled):
		return &Failure{FailCancelled, "run cancelled"}
	case errors.Is(run.Err(), context.DeadlineExceeded):
		return &Failure{FailRunTimeout, "whole-run timeout reached"}
	case st.policy != nil:
		return st.policy
	case errors.Is(req.Err(), context.DeadlineExceeded), isTimeout(err):
		return &Failure{FailTimeout, "request timeout exceeded"}
	case errors.Is(err, io.ErrUnexpectedEOF):
		return &Failure{FailTruncated, "stream ended before the declared length"}
	case isTLS(err):
		return &Failure{FailTLS, "TLS verification failed (private CA? see --ca-file): " + msg}
	}
	return &Failure{FailNetwork, msg}
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

func isTLS(err error) bool {
	var (
		ua x509.UnknownAuthorityError
		he x509.HostnameError
		ci x509.CertificateInvalidError
		cv *tls.CertificateVerificationError
	)
	return errors.As(err, &ua) || errors.As(err, &he) || errors.As(err, &ci) || errors.As(err, &cv)
}

// checkRedirect enforces the redirect policy:
//   - at most MaxRedirects hops;
//   - only http and https targets, never https -> http;
//   - no credentials in the target URL;
//   - user-supplied headers and If-Match are removed when the target origin
//     differs from the initial origin; Referer is always removed because it
//     would leak the (possibly signed) source URL.
func (c *Client) checkRedirect(req *http.Request, via []*http.Request) error {
	st, _ := req.Context().Value(stateKey{}).(*fetchState)
	if st == nil {
		st = &fetchState{origin: via[0].URL}
	}
	prev := via[len(via)-1]
	refuse := func(kind FailKind, msg string) error {
		st.policy = &Failure{kind, msg}
		return errors.New(msg)
	}
	if len(via) > c.cfg.MaxRedirects {
		return refuse(FailRedirectLimit, fmt.Sprintf("more than %d redirects", c.cfg.MaxRedirects))
	}
	switch {
	case req.URL.Scheme != "http" && req.URL.Scheme != "https":
		return refuse(FailRedirectRefused, "redirect to unsupported scheme "+redact.Clean(req.URL.Scheme, 16))
	case prev.URL.Scheme == "https" && req.URL.Scheme == "http":
		return refuse(FailRedirectRefused, "redirect would downgrade https to http")
	case req.URL.User != nil:
		return refuse(FailRedirectRefused, "redirect target contains credentials")
	case req.URL.Host == "":
		return refuse(FailRedirectRefused, "redirect target has no host")
	}
	req.Header.Del("Referer")
	if !SameOrigin(st.origin, req.URL) {
		for name := range c.cfg.Headers {
			req.Header.Del(name)
		}
		for _, name := range []string{"Authorization", "Cookie", "Proxy-Authorization", "If-Match"} {
			req.Header.Del(name)
		}
	}
	status := 0
	if req.Response != nil {
		status = req.Response.StatusCode
	}
	st.hops = append(st.hops, Hop{Status: status, From: prev.URL.String(), To: req.URL.String()})
	return nil
}

// SameOrigin compares scheme, host and effective port.
func SameOrigin(a, b *url.URL) bool {
	return strings.EqualFold(a.Scheme, b.Scheme) &&
		strings.EqualFold(a.Hostname(), b.Hostname()) &&
		port(a) == port(b)
}

func port(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	if strings.EqualFold(u.Scheme, "https") {
		return "443"
	}
	return "80"
}
