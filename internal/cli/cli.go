// Package cli implements the rangeprobe command line.
package cli

import (
	"context"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/0then0/rangeprobe/internal/model"
	"github.com/0then0/rangeprobe/internal/probe"
	"github.com/0then0/rangeprobe/internal/redact"
	"github.com/0then0/rangeprobe/internal/reference"
	"github.com/0then0/rangeprobe/internal/report"
	"github.com/0then0/rangeprobe/internal/version"
)

const usageText = `RangeProbe checks whether a published file can be read in parts over HTTP.

Usage:
  rangeprobe reference [flags] URL FILE   compare range responses with a local reference file
  rangeprobe observe   [flags] URL        check the consistency of range responses without a reference
  rangeprobe if-range  [flags] URL        check conditional download resume with entity-tags
  rangeprobe version

Reference mode assumes FILE is byte-identical to the currently published file.
Observe mode cannot show that bytes are correct, only that the answers are consistent.

Flags:
  --max-requests N          most requests to send (default 16, max 100)
  --max-bytes SIZE          most body bytes to read over the whole run (default 8MiB, max 1GiB)
  --max-response-bytes SIZE most body bytes to read from one response (default 2MiB)
  --probe-size SIZE         length of the sampled ranges (default 4KiB)
  --request-timeout D       timeout per request including its body (default 30s)
  --timeout D               timeout of the whole run (default 2m)
  --max-redirects N         redirects followed per request (default 5, max 20)
  -H, --header 'Name: value'  extra request header, repeatable; values may use ${ENV_VAR}
  --header-file PATH        file with one 'Name: value' per line (owner-only permissions)
  --ca-file PATH            extra PEM CA certificates to trust (TLS verification is always on)
  --preconditions           send If-Match with the first strong ETag seen (observe/reference)
  --weak-if-range           opt-in invalid-client weak validator conformance probe (if-range only)
  --json PATH               write the JSON report ('-' for stdout)
  --html PATH               write a standalone HTML report
  --force                   overwrite existing report files
  --no-redact               keep URL query values and full local paths in reports
  --dump-mismatch N         include up to N (max 64) bytes around the first mismatch (privacy risk)
  -q, --quiet               do not print the text summary

SIZE accepts B, KiB, MiB, GiB suffixes (for example 64KiB).

Exit codes:
  0    all key checks passed
  1    confirmed problem: protocol violation or byte mismatch with the reference
  2    the server ignored Range (no random access); no violation confirmed
  3    incomplete: checks were inconclusive, skipped or failed; no confirmed problem
  64   invalid command line or input file
  70   the run or its output failed
  130  interrupted
`

// Run executes the CLI and returns the process exit code.
func Run(ctx context.Context, args []string, stdout, stderr io.Writer, getenv func(string) string) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usageText)
		return model.ExitUsage
	}
	switch args[0] {
	case "-h", "--help", "help":
		fmt.Fprint(stdout, usageText)
		return 0
	case "version", "-version", "--version":
		printVersion(stdout)
		return 0
	case "reference", "observe", "if-range":
		return runProbe(ctx, args[0], args[1:], stdout, stderr, getenv)
	}
	fmt.Fprintf(stderr, "rangeprobe: unknown command %q\n\n%s", args[0], usageText)
	return model.ExitUsage
}

func printVersion(w io.Writer) {
	fmt.Fprintf(w, "rangeprobe %s (%s %s/%s)\n", version.Version, runtime.Version(), runtime.GOOS, runtime.GOARCH)
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, s := range bi.Settings {
			if s.Key == "vcs.revision" && s.Value != "" {
				fmt.Fprintf(w, "commit %s\n", s.Value)
			}
		}
	}
	fmt.Fprintln(w, version.Repository)
}

type strList []string

func (s *strList) String() string     { return strings.Join(*s, ",") }
func (s *strList) Set(v string) error { *s = append(*s, v); return nil }

type sizeFlag int64

func (s *sizeFlag) String() string { return strconv.FormatInt(int64(*s), 10) }
func (s *sizeFlag) Set(v string) error {
	n, err := ParseSize(v)
	if err != nil {
		return err
	}
	*s = sizeFlag(n)
	return nil
}

// ParseSize parses a non-negative byte count with an optional binary suffix.
func ParseSize(v string) (int64, error) {
	v = strings.TrimSpace(v)
	mult := int64(1)
	for _, u := range []struct {
		suffix string
		mult   int64
	}{{"GiB", 1 << 30}, {"MiB", 1 << 20}, {"KiB", 1 << 10}, {"B", 1}} {
		if strings.HasSuffix(v, u.suffix) {
			v, mult = strings.TrimSuffix(v, u.suffix), u.mult
			break
		}
	}
	n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("invalid size %q", v)
	}
	if n > (1<<62)/mult {
		return 0, fmt.Errorf("size %q is too large", v)
	}
	return n * mult, nil
}

type config struct {
	maxRequests    int
	maxBytes       sizeFlag
	maxResponse    sizeFlag
	probeSize      sizeFlag
	requestTimeout time.Duration
	timeout        time.Duration
	maxRedirects   int
	headers        strList
	headerFile     string
	caFile         string
	weakIfRange    bool
	preconditions  bool
	jsonPath       string
	htmlPath       string
	force          bool
	noRedact       bool
	dump           int
	quiet          bool
}

func runProbe(ctx context.Context, mode string, args []string, stdout, stderr io.Writer, getenv func(string) string) int {
	var c config
	c.maxBytes, c.maxResponse, c.probeSize = 8<<20, 2<<20, 4<<10
	fs := flag.NewFlagSet("rangeprobe "+mode, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.IntVar(&c.maxRequests, "max-requests", 16, "")
	fs.Var(&c.maxBytes, "max-bytes", "")
	fs.Var(&c.maxResponse, "max-response-bytes", "")
	fs.Var(&c.probeSize, "probe-size", "")
	fs.DurationVar(&c.requestTimeout, "request-timeout", 30*time.Second, "")
	fs.DurationVar(&c.timeout, "timeout", 2*time.Minute, "")
	fs.IntVar(&c.maxRedirects, "max-redirects", 5, "")
	fs.Var(&c.headers, "H", "")
	fs.Var(&c.headers, "header", "")
	fs.StringVar(&c.headerFile, "header-file", "", "")
	fs.StringVar(&c.caFile, "ca-file", "", "")
	fs.BoolVar(&c.weakIfRange, "weak-if-range", false, "")
	fs.BoolVar(&c.preconditions, "preconditions", false, "")
	fs.StringVar(&c.jsonPath, "json", "", "")
	fs.StringVar(&c.htmlPath, "html", "", "")
	fs.BoolVar(&c.force, "force", false, "")
	fs.BoolVar(&c.noRedact, "no-redact", false, "")
	fs.IntVar(&c.dump, "dump-mismatch", 0, "")
	fs.BoolVar(&c.quiet, "q", false, "")
	fs.BoolVar(&c.quiet, "quiet", false, "")

	var pos []string
	rest := args
	for {
		if err := fs.Parse(rest); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				fmt.Fprint(stdout, usageText)
				return 0
			}
			return usageErr(stderr, "%v", err)
		}
		if fs.NArg() == 0 {
			break
		}
		pos = append(pos, fs.Arg(0))
		rest = fs.Args()[1:]
	}
	want := 1
	if mode == "reference" {
		want = 2
	}
	if len(pos) != want {
		if mode == "reference" {
			return usageErr(stderr, "reference mode takes URL and FILE (got %d argument(s))", len(pos))
		}
		return usageErr(stderr, "%s mode takes exactly one URL (got %d argument(s))", mode, len(pos))
	}

	if mode == "if-range" && c.preconditions {
		return usageErr(stderr, "--preconditions cannot be combined with if-range")
	}
	if mode != "if-range" && c.weakIfRange {
		return usageErr(stderr, "--weak-if-range requires if-range mode")
	}
	target, err := parseTarget(pos[0])
	if err != nil {
		return usageErr(stderr, "%v", err)
	}
	if err := c.validate(); err != nil {
		return usageErr(stderr, "%v", err)
	}
	headers, err := collectHeaders(c.headers, c.headerFile, getenv)
	if err != nil {
		return usageErr(stderr, "%v", err)
	}
	if mode == "if-range" {
		for _, name := range []string{"If-None-Match", "If-Modified-Since", "If-Unmodified-Since"} {
			if len(headers.Values(name)) > 0 {
				return usageErr(stderr, "%s changes conditional semantics and is not accepted in if-range mode", name)
			}
		}
	}
	var pool *x509.CertPool
	if c.caFile != "" {
		if pool, err = loadCA(c.caFile); err != nil {
			return usageErr(stderr, "%v", err)
		}
	}
	var ref *reference.File
	if mode == "reference" {
		if ref, err = reference.Open(pos[1]); err != nil {
			return usageErr(stderr, "reference file: %v", err)
		}
		defer ref.Close()
	}
	for _, out := range []string{c.jsonPath, c.htmlPath} {
		if err := checkOutput(out, ref, c.force); err != nil {
			return usageErr(stderr, "%v", err)
		}
	}
	if c.jsonPath != "" && c.jsonPath == c.htmlPath {
		return usageErr(stderr, "--json and --html name the same file")
	}

	if c.dump > 0 {
		fmt.Fprintf(stderr, "warning: --dump-mismatch puts up to %d bytes of file content into the reports; they may be private\n", c.dump)
	}
	if c.noRedact {
		fmt.Fprintln(stderr, "warning: --no-redact keeps URL query values and full local paths in the reports; they may contain secrets")
	}
	for _, h := range c.headers {
		if !strings.Contains(h, "${") {
			fmt.Fprintln(stderr, "note: header values passed with -H are visible in the process list; use ${ENV_VAR} or --header-file for secrets")
			break
		}
	}

	rep := probe.Run(ctx, probe.Options{
		URL: target, Ref: ref, Headers: headers, ProbeSize: int64(c.probeSize),
		Budgets: probe.Budgets{
			MaxRequests: c.maxRequests, MaxBytes: int64(c.maxBytes), MaxBody: int64(c.maxResponse),
			RequestTimeout: c.requestTimeout, RunTimeout: c.timeout, MaxRedirects: c.maxRedirects,
		},
		IfRange: mode == "if-range", WeakIfRange: c.weakIfRange,
		Preconditions: c.preconditions, RootCAs: pool, CustomCA: pool != nil,
		Redactor: redact.New(!c.noRedact), DumpMismatch: c.dump,
	})

	code := rep.Summary.ExitCode
	if rep.Run.Interrupted && code == model.ExitIncomplete {
		code = model.ExitInterrupted
	}
	textOut := stdout
	if c.jsonPath == "-" {
		textOut = stderr
	}
	if !c.quiet {
		report.Text(textOut, rep)
	}
	if err := writeReports(c, rep, stdout); err != nil {
		fmt.Fprintf(stderr, "rangeprobe: %v\n", err)
		return model.ExitRunError
	}
	return code
}

func writeReports(c config, rep *model.Report, stdout io.Writer) error {
	if c.jsonPath != "" {
		b, err := report.JSON(rep)
		if err != nil {
			return err
		}
		if c.jsonPath == "-" {
			if _, err := stdout.Write(b); err != nil {
				return err
			}
		} else if err := report.WriteFile(c.jsonPath, b, c.force); err != nil {
			return fmt.Errorf("JSON report: %w", err)
		}
	}
	if c.htmlPath != "" {
		b, err := report.HTML(rep)
		if err != nil {
			return err
		}
		if err := report.WriteFile(c.htmlPath, b, c.force); err != nil {
			return fmt.Errorf("HTML report: %w", err)
		}
	}
	return nil
}

func usageErr(w io.Writer, format string, a ...any) int {
	fmt.Fprintf(w, "rangeprobe: "+format+"\nRun 'rangeprobe help' for usage.\n", a...)
	return model.ExitUsage
}

func (c *config) validate() error {
	switch {
	case c.maxRequests < 1 || c.maxRequests > 100:
		return errors.New("--max-requests must be between 1 and 100")
	case c.maxBytes < 1 || c.maxBytes > 1<<30:
		return errors.New("--max-bytes must be between 1B and 1GiB")
	case c.maxResponse < 2 || c.maxResponse > c.maxBytes:
		return errors.New("--max-response-bytes must be at least 2B and not above --max-bytes")
	case c.probeSize < 1 || c.probeSize >= c.maxResponse:
		return errors.New("--probe-size must be at least 1B and below --max-response-bytes")
	case c.requestTimeout <= 0 || c.requestTimeout > time.Hour:
		return errors.New("--request-timeout must be positive and at most 1h")
	case c.timeout <= 0 || c.timeout > 24*time.Hour:
		return errors.New("--timeout must be positive and at most 24h")
	case c.maxRedirects < 0 || c.maxRedirects > 20:
		return errors.New("--max-redirects must be between 0 and 20")
	case c.dump < 0 || c.dump > 64:
		return errors.New("--dump-mismatch must be between 0 and 64")
	}
	return nil
}

func parseTarget(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid URL: %s", redact.New(true).Text(err.Error()))
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", errors.New("URL must use http or https")
	}
	if u.Hostname() == "" {
		return "", errors.New("URL has no host")
	}
	if u.User != nil {
		return "", errors.New("credentials in the URL are not accepted; use --header or --header-file")
	}
	u.Fragment = ""
	return u.String(), nil
}

func checkOutput(path string, ref *reference.File, force bool) error {
	if path == "" || path == "-" {
		return nil
	}
	// Fail before the probe runs, not after it: the directory must exist.
	dir := filepath.Dir(path)
	if ds, err := os.Stat(dir); err != nil || !ds.IsDir() {
		return fmt.Errorf("report directory %q does not exist", dir)
	}
	st, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if ref != nil {
		if rs, err := os.Stat(ref.Path()); err == nil && os.SameFile(st, rs) {
			return fmt.Errorf("%s is the reference file; refusing to write a report over it", path)
		}
	}
	if !force {
		return fmt.Errorf("%s already exists (use --force to overwrite)", path)
	}
	return nil
}

var headerName = regexp.MustCompile("^[!#$%&'*+\\-.^_`|~0-9A-Za-z]+$")

var reservedHeaders = map[string]bool{
	"range": true, "if-range": true, "if-match": true, "accept-encoding": true, "host": true,
	"content-length": true, "transfer-encoding": true, "connection": true, "te": true, "upgrade": true,
}

func collectHeaders(flags []string, file string, getenv func(string) string) (http.Header, error) {
	lines := append([]string(nil), flags...)
	if file != "" {
		fl, err := readHeaderFile(file)
		if err != nil {
			return nil, err
		}
		lines = append(lines, fl...)
	}
	h := http.Header{}
	for _, l := range lines {
		name, val, ok := strings.Cut(l, ":")
		name, val = strings.TrimSpace(name), strings.TrimSpace(val)
		if !ok || !headerName.MatchString(name) {
			return nil, fmt.Errorf("invalid header %q: expected 'Name: value'", redact.Clean(name, 40))
		}
		if reservedHeaders[strings.ToLower(name)] {
			return nil, fmt.Errorf("header %s is set by RangeProbe and cannot be overridden", name)
		}
		exp, err := expandEnv(val, getenv)
		if err != nil {
			return nil, fmt.Errorf("header %s: %w", name, err)
		}
		if strings.ContainsAny(exp, "\r\n\x00") {
			return nil, fmt.Errorf("header %s contains a control character", name)
		}
		h.Add(name, exp)
	}
	return h, nil
}

var envRef = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

func expandEnv(v string, getenv func(string) string) (string, error) {
	var missing string
	out := envRef.ReplaceAllStringFunc(v, func(m string) string {
		name := m[2 : len(m)-1]
		val := getenv(name)
		if val == "" {
			missing = name
		}
		return val
	})
	if missing != "" {
		return "", fmt.Errorf("environment variable %s is not set", missing)
	}
	return out, nil
}

func readHeaderFile(path string) ([]string, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("header file: %w", err)
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("header file %s is not a regular file", path)
	}
	if runtime.GOOS != "windows" && st.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("header file %s is readable by other users (mode %04o); run chmod 600 on it", path, st.Mode().Perm())
	}
	if st.Size() > 64<<10 {
		return nil, fmt.Errorf("header file %s is larger than 64 KiB", path)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("header file: %w", err)
	}
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		out = append(out, l)
	}
	return out, nil
}

func loadCA(path string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("CA file: %w", err)
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("CA file %s contains no PEM certificates", path)
	}
	return pool, nil
}
