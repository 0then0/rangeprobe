// Command rangeprobe checks whether a published file can be read in parts
// over HTTP. See the README for usage.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/0then0/rangeprobe/internal/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := cli.Run(ctx, os.Args[1:], os.Stdout, os.Stderr, os.Getenv)
	stop()
	os.Exit(code)
}
