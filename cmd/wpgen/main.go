package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/kubewarden/runtime-enforcer/internal/imagescan"
	"github.com/kubewarden/runtime-enforcer/internal/wpgen"
)

func main() {
	os.Exit(run())
}

func run() int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// After the first signal, wpgen stops its work and cleans up. Restore the
	// default handling of the signals, so that a second signal ends wpgen at
	// once, without the cleanup.
	context.AfterFunc(ctx, stop)
	defer imagescan.CleanupAll()

	return wpgen.Execute(ctx)
}
