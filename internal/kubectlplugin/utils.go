package kubectlplugin

import (
	"context"
	"fmt"
	"time"

	"github.com/kubewarden/runtime-enforcer/api/v1alpha1"
	securityclient "github.com/kubewarden/runtime-enforcer/pkg/generated/clientset/versioned/typed/api/v1alpha1"
	"github.com/spf13/cobra"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/cli-runtime/pkg/genericiooptions"
	"k8s.io/client-go/kubernetes"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	cmdutil "k8s.io/kubectl/pkg/cmd/util"
)

const (
	resourceWorkloadPolicies = "workloadpolicies"
)

type commonCmdDeps struct {
	f cmdutil.Factory

	ioStreams genericiooptions.IOStreams
}

// groupUsageTemplate is a custom usage template for group commands (e.g. "proposal", "policy").
const groupUsageTemplate = `Usage:
  {{.UseLine}}

Available Commands:
{{range .Commands}}{{if (or .IsAvailableCommand (eq .Name "help"))}}  {{rpad .Name .NamePadding}} {{.Short}}
{{end}}{{end}}
Flags:
{{.LocalFlags.FlagUsages | trimTrailingWhitespaces}}
`

// subcommandUsageTemplate is a custom usage template for subcommands:
// it does not print the "Available Commands" section.
const subcommandUsageTemplate = `Usage:
  {{.UseLine}}

Flags:
{{.LocalFlags.FlagUsages | trimTrailingWhitespaces}}
`

const (
	defaultOperationTimeout = 30 * time.Second
	defaultPollInterval     = 500 * time.Millisecond
)

type commonOptions struct {
	cmdutil.Factory

	ioStreams genericiooptions.IOStreams

	Namespace string
	DryRun    bool
}

func newCommonOptions(deps commonCmdDeps) commonOptions {
	return commonOptions{
		Factory:   deps.f,
		ioStreams: deps.ioStreams,
	}
}

type subcommandFunc func(
	ctx context.Context,
	securityClient securityclient.SecurityV1alpha1Interface,
) error

type subcommandWithCoreFunc func(
	ctx context.Context,
	securityClient securityclient.SecurityV1alpha1Interface,
	coreClient corev1client.CoreV1Interface,
) error

// buildSecurityClient resolves the namespace, builds the REST config and creates the runtime-enforcer security client.
// It also populates opts.Namespace as a side effect.
func buildSecurityClient(opts *commonOptions) (securityclient.SecurityV1alpha1Interface, error) {
	namespace, _, err := opts.Factory.ToRawKubeConfigLoader().Namespace()
	if err != nil {
		return nil, fmt.Errorf("failed to determine namespace: %w", err)
	}
	opts.Namespace = namespace

	config, err := opts.Factory.ToRESTConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to build Kubernetes configuration: %w", err)
	}

	securityClient, err := securityclient.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create runtime-enforcer client: %w", err)
	}

	return securityClient, nil
}

// withRuntimeEnforcerClient is a helper function to create a runtime-enforcer client and execute a subcommand.
func withRuntimeEnforcerClient(
	cmd *cobra.Command,
	opts *commonOptions,
	subcommand subcommandFunc,
) error {
	securityClient, err := buildSecurityClient(opts)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(cmd.Context(), defaultOperationTimeout)
	defer cancel()

	return subcommand(ctx, securityClient)
}

// withRuntimeEnforcerAndCoreClient is a helper function to create a runtime-enforcer and Kubernetes core client.
func withRuntimeEnforcerAndCoreClient(
	cmd *cobra.Command,
	opts *commonOptions,
	subcommand subcommandWithCoreFunc,
) error {
	securityClient, err := buildSecurityClient(opts)
	if err != nil {
		return err
	}

	config, err := opts.Factory.ToRESTConfig()
	if err != nil {
		return fmt.Errorf("failed to build Kubernetes configuration: %w", err)
	}

	kubeClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("failed to create Kubernetes client: %w", err)
	}

	ctx, cancel := context.WithTimeout(cmd.Context(), defaultOperationTimeout)
	defer cancel()

	return subcommand(ctx, securityClient, kubeClient.CoreV1())
}

func getWorkloadPolicy(
	ctx context.Context,
	client securityclient.SecurityV1alpha1Interface,
	namespace, name string,
) (*v1alpha1.WorkloadPolicy, error) {
	policy, err := client.WorkloadPolicies(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil, fmt.Errorf("workloadpolicy %q not found in namespace %q", name, namespace)
		}
		return nil, fmt.Errorf(
			"failed to get WorkloadPolicy %q in namespace %q: %w",
			name,
			namespace,
			err,
		)
	}
	return policy, nil
}

func updateWorkloadPolicy(
	ctx context.Context,
	client securityclient.SecurityV1alpha1Interface,
	namespace string,
	policy *v1alpha1.WorkloadPolicy,
	dryRun bool,
) error {
	updateOptions := metav1.UpdateOptions{}
	if dryRun {
		updateOptions.DryRun = []string{metav1.DryRunAll}
	}

	if _, err := client.WorkloadPolicies(namespace).Update(ctx, policy, updateOptions); err != nil {
		if apierrors.IsConflict(err) {
			return fmt.Errorf(
				"WorkloadPolicy %q in namespace %q was modified concurrently",
				policy.Name,
				policy.Namespace,
			)
		}
		return fmt.Errorf(
			"failed to update WorkloadPolicy %q in namespace %q: %w",
			policy.Name,
			policy.Namespace,
			err,
		)
	}

	return nil
}
