package main

import (
	"os"

	"github.com/kubewarden/runtime-enforcer/internal/kubectlplugin"
	_ "k8s.io/client-go/plugin/pkg/client/auth"
)

func main() {
	cmd := kubectlplugin.NewRootCmd()
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
