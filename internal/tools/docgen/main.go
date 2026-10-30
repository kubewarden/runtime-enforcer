package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"slices"

	"github.com/spf13/cobra"

	"github.com/kubewarden/runtime-enforcer/internal/kubectlplugin"
	"github.com/kubewarden/runtime-enforcer/internal/wpgen"
)

const (
	toolKubectlPlugin = "kubectl-plugin"
	toolWpgen         = "wpgen"

	defaultOut = "docs/kubectl-plugin/cli-docs.adoc"
)

// rootCmd returns the command tree of the tool, and the prefix that goes in
// front of each command path.
func rootCmd(tool string) (*cobra.Command, string, error) {
	switch tool {
	case toolKubectlPlugin:
		_ = os.Setenv("KUBECACHEDIR", "$HOME/.kube/cache")
		return kubectlplugin.NewRootCmd(), "kubectl ", nil
	case toolWpgen:
		return wpgen.NewRootCmd(), "", nil
	default:
		valid := []string{toolKubectlPlugin, toolWpgen}
		slices.Sort(valid)
		return nil, "", fmt.Errorf("unknown tool %q, valid values: %v", tool, valid)
	}
}

func main() {
	tool := flag.String("tool", toolKubectlPlugin, "tool to document: kubectl-plugin or wpgen")
	out := flag.String("out", defaultOut, "output file for the AsciiDoc CLI reference")
	flag.Parse()

	root, prefix, err := rootCmd(*tool)
	if err != nil {
		log.Fatal(err)
	}

	if err = os.MkdirAll(filepath.Dir(*out), 0o750); err != nil {
		log.Fatal(err)
	}

	f, err := os.Create(*out)
	if err != nil {
		log.Fatal(err)
	}

	err = genASCIIDoc(root, prefix, f)
	if err != nil {
		_ = f.Close()
		log.Fatal(err)
	}

	// Close is not deferred. A write error can surface at Close, and a
	// truncated file must not exit 0.
	err = f.Close()
	if err != nil {
		log.Fatal(err)
	}
}
