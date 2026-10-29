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
	defer imagescan.CleanupAll()

	if err := wpgen.NewRootCmd().ExecuteContext(ctx); err != nil {
		return 1
	}
	return 0
}
