package main

import (
	"flag"
	"log"
	"os"

	"github.com/kubewarden/runtime-enforcer/internal/kubectlplugin"
	"github.com/spf13/cobra/doc"
)

const defaultOut = "docs/kubectl-plugin"

func main() {
	out := flag.String("out", defaultOut, "output directory for Markdown files")
	flag.Parse()

	if err := os.MkdirAll(*out, 0o750); err != nil {
		log.Fatal(err)
	}

	_ = os.Setenv("KUBECACHEDIR", "$HOME/.kube/cache")

	if err := doc.GenMarkdownTree(kubectlplugin.NewRootCmd(), *out); err != nil {
		log.Fatal(err)
	}
}
