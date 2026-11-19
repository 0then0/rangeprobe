package cli

import (
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"

	"github.com/0then0/rangeprobe/internal/model"
	"github.com/0then0/rangeprobe/internal/probe"
	"github.com/0then0/rangeprobe/internal/rangespec"
	"github.com/0then0/rangeprobe/internal/redact"
	"github.com/0then0/rangeprobe/internal/reference"
	"github.com/0then0/rangeprobe/internal/report"
	"github.com/0then0/rangeprobe/internal/transport"
)

func runMultipart(ctx context.Context, c config, target string, ref *reference.File, requested [2]rangespec.Spec, headers http.Header, pool *x509.CertPool, stdout, stderr io.Writer) int {
	rd := redact.New(!c.noRedact)
	rd.AddURL(target)
	for _, values := range headers {
		for _, value := range values {
			rd.AddSecret(value)
		}
	}
	cl := transport.New(transport.Config{
		Headers: headers, RequestTimeout: c.requestTimeout, MaxRedirects: c.maxRedirects,
		RootCAs: pool, Redactor: rd, MaxResponseHeaderBytes: 64 << 10,
		SkipRedirectBodies: true,
	})
	run, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	rep := probe.Multipart(run, cl, target, ref, requested, int64(min(c.maxBytes, c.maxResponse)), rd)

	textOut := stdout
	if c.jsonPath == "-" {
		textOut = stderr
	}
	code := rep.ExitCode
	if !c.quiet {
		if _, err := textOut.Write(report.MultipartText(rep)); err != nil {
			fmt.Fprintf(stderr, "rangeprobe: text report: %v\n", err)
			code = model.ExitRunError
		}
	}
	if c.jsonPath != "" {
		b, err := report.MultipartJSON(rep)
		if err == nil {
			err = writeJSON(c, b, stdout)
		}
		if err != nil {
			fmt.Fprintf(stderr, "rangeprobe: %v\n", err)
			return model.ExitRunError
		}
	}
	return code
}
