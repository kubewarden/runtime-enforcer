package kubectlplugin

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"html/template"
	"io"
	"strconv"
	"strings"

	"github.com/kubewarden/runtime-enforcer/api/v1alpha1"
	securityclient "github.com/kubewarden/runtime-enforcer/pkg/generated/clientset/versioned/typed/api/v1alpha1"
	"github.com/spf13/cobra"
	"k8s.io/kubectl/pkg/util/completion"
)

type policyAckOptions struct {
	commonOptions

	PolicyName  string
	ViolationID int64
	Reason      string
	reasonSet   bool
}

const (
	minPolicyAckArgs = 2

	violationIDCompletionTemplate = "{{ range .status.violations }}{{ printf \"%d\" .id }}\t{{ .executablePath }} {{end}}"
)

func newPolicyAckValidArgsFunction(
	deps commonCmdDeps,
) func(cmd *cobra.Command, args []string, toComplete string) ([]cobra.Completion, cobra.ShellCompDirective) {
	const (
		positionPolicyName  = 0
		positionViolationID = 1
	)

	return func(_ *cobra.Command, args []string, toComplete string) ([]cobra.Completion, cobra.ShellCompDirective) {
		switch len(args) {
		case positionPolicyName:
			return completion.CompGetResource(
				deps.f,
				resourceWorkloadPolicies,
				toComplete,
			), cobra.ShellCompDirectiveNoFileComp
		case positionViolationID:
			templateStr := violationIDCompletionTemplate
			if _, err := template.New("").Parse(templateStr); err != nil {
				return nil, cobra.ShellCompDirectiveNoFileComp
			}
			return completion.CompGetFromTemplate(
				&templateStr,
				deps.f,
				"",
				[]string{resourceWorkloadPolicies, args[0]},
				toComplete,
			), cobra.ShellCompDirectiveNoFileComp
		default:
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
	}
}

func newPolicyAckCmd(deps commonCmdDeps) *cobra.Command {
	opts := &policyAckOptions{
		commonOptions: newCommonOptions(deps),
	}

	cmd := &cobra.Command{
		Use:               "ack POLICY_NAME <violation-id> [--reason <reason>]",
		Short:             "Acknowledge a WorkloadPolicy violation",
		Args:              cobra.ExactArgs(minPolicyAckArgs),
		RunE:              runPolicyAckCmd(opts),
		ValidArgsFunction: newPolicyAckValidArgsFunction(deps),
	}

	cmd.SetUsageTemplate(subcommandUsageTemplate)

	cmd.Flags().BoolVar(&opts.DryRun, "dry-run", false, "Show what would happen without making any changes")
	cmd.Flags().
		StringVar(&opts.Reason, "reason", "", "Reason for acknowledging the violation. If omitted, you will be prompted")

	return cmd
}

func runPolicyAckCmd(opts *policyAckOptions) func(cmd *cobra.Command, args []string) error {
	return func(cmd *cobra.Command, args []string) error {
		opts.PolicyName = args[0]
		opts.reasonSet = cmd.Flags().Changed("reason")

		violationID, err := strconv.ParseInt(args[1], 10, 64)
		if err != nil {
			return fmt.Errorf("invalid violation id %q: must be a decimal integer", args[1])
		}
		opts.ViolationID = violationID

		return withRuntimeEnforcerClient(cmd, &opts.commonOptions, func(
			ctx context.Context,
			securityClient securityclient.SecurityV1alpha1Interface,
		) error {
			return runPolicyAck(ctx, securityClient, opts, opts.ioStreams.In, opts.ioStreams.Out, opts.ioStreams.ErrOut)
		})
	}
}

func runPolicyAck(
	ctx context.Context,
	client securityclient.SecurityV1alpha1Interface,
	opts *policyAckOptions,
	stdin io.Reader,
	stdout, stderr io.Writer,
) error {
	var reason string
	var violation v1alpha1.ViolationRecord

	policy, err := getWorkloadPolicy(ctx, client, opts.Namespace, opts.PolicyName)
	if err != nil {
		return err
	}

	violation, err = findViolationByID(policy.Status.Violations, opts.ViolationID)
	if err != nil {
		return err
	}

	reason, err = resolveAckReason(opts, stdin, stderr)
	if err != nil {
		return err
	}

	annotationKey, unchanged := applyAckAnnotation(policy, opts.ViolationID, reason)
	if unchanged {
		fmt.Fprintf(
			stdout,
			"No changes required for WorkloadPolicy %q in namespace %q.\n",
			policy.Name,
			policy.Namespace,
		)
		return nil
	}

	if opts.DryRun {
		printPolicyAckDryRun(stdout, opts, policy, violation, annotationKey, reason)
	}

	if err = updateWorkloadPolicy(ctx, client, opts.Namespace, policy, opts.DryRun); err != nil {
		return err
	}

	fmt.Fprintf(
		stdout,
		"Successfully acknowledged violation %d for WorkloadPolicy %q in namespace %q.\n",
		opts.ViolationID,
		policy.Name,
		policy.Namespace,
	)

	if opts.DryRun {
		fmt.Fprint(stdout, "Dry-run completed; no changes were persisted.\n")
	}

	return nil
}

func applyAckAnnotation(
	policy *v1alpha1.WorkloadPolicy,
	violationID int64,
	reason string,
) (string, bool) {
	annotationKey := violationAcknowledgeAnnotationKey(violationID)
	if policy.Annotations != nil {
		if existingReason, found := policy.Annotations[annotationKey]; found && existingReason == reason {
			return annotationKey, true
		}
	}

	if policy.Annotations == nil {
		policy.Annotations = make(map[string]string)
	}
	policy.Annotations[annotationKey] = reason
	return annotationKey, false
}

func printPolicyAckDryRun(
	out io.Writer,
	opts *policyAckOptions,
	policy *v1alpha1.WorkloadPolicy,
	violation v1alpha1.ViolationRecord,
	annotationKey, reason string,
) {
	fmt.Fprintf(
		out,
		"Would acknowledge violation %d for WorkloadPolicy %q in namespace %q.\n",
		opts.ViolationID,
		policy.Name,
		policy.Namespace,
	)
	fmt.Fprintf(out, "  Annotation %s: %q\n", annotationKey, reason)
	fmt.Fprintf(
		out,
		"  Violation executable: %q in container %q on pod %q\n",
		violation.ExecutablePath,
		violation.ContainerName,
		violation.PodName,
	)
}

func resolveAckReason(opts *policyAckOptions, in io.Reader, errOut io.Writer) (string, error) {
	var reason string
	if opts.reasonSet {
		reason = opts.Reason
	} else {
		fmt.Fprint(errOut, "Reason for acknowledgement: ")
		reader := bufio.NewReader(in)
		line, err := reader.ReadString('\n')
		if err != nil {
			return "", fmt.Errorf("failed to read acknowledgement reason: %w", err)
		}
		reason = strings.TrimRight(line, "\r\n")
	}

	reason = strings.TrimSpace(reason)
	if reason == "" {
		return "", errors.New("acknowledgement reason is required; provide --reason or enter a reason when prompted")
	}

	return reason, nil
}

func findViolationByID(violations []v1alpha1.ViolationRecord, id int64) (v1alpha1.ViolationRecord, error) {
	for _, violation := range violations {
		if violation.ID == id {
			return violation, nil
		}
	}

	return v1alpha1.ViolationRecord{}, fmt.Errorf(
		"violation id %d not found in status.violations",
		id,
	)
}

func violationAcknowledgeAnnotationKey(id int64) string {
	return v1alpha1.ViolationAcknowledgePrefix + strconv.FormatInt(id, 10)
}
