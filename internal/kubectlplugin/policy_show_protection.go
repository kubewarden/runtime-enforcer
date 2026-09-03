package kubectlplugin

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/kubewarden/runtime-enforcer/api/v1alpha1"
	"github.com/kubewarden/runtime-enforcer/internal/podworkload"
	"github.com/kubewarden/runtime-enforcer/internal/types/policymode"
	securityclient "github.com/kubewarden/runtime-enforcer/pkg/generated/clientset/versioned/typed/api/v1alpha1"
	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/cli-runtime/pkg/printers"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
)

const (
	policyShowProtectionOutputTable = "table"
	policyShowProtectionOutputJSON  = "json"

	unknownMode   = "Unknown"
	missingStatus = "Missing"
)

type policyShowProtectionOptions struct {
	commonOptions

	Output        string
	AllNamespaces bool
}

type workloadProtectionRow struct {
	Workload string `json:"workload"`
	Kind     string `json:"kind"`
	Policy   string `json:"policy"`
	Mode     string `json:"mode"`
	Status   string `json:"status"`
}

func newPolicyShowProtectionCmd(deps commonCmdDeps) *cobra.Command {
	opts := &policyShowProtectionOptions{
		commonOptions: newCommonOptions(deps),
		Output:        policyShowProtectionOutputTable,
	}

	cmd := &cobra.Command{
		Use:   "protection",
		Short: "List workloads to WorkloadPolicy protection mapping",
		Args:  cobra.NoArgs,
		RunE:  runPolicyShowProtectionCmd(opts),
	}

	cmd.SetUsageTemplate(subcommandUsageTemplate)

	cmd.Flags().StringVarP(
		&opts.Output,
		"output",
		"o",
		policyShowProtectionOutputTable,
		"Output format. One of: table|json",
	)
	cmd.Flags().BoolVarP(
		&opts.AllNamespaces,
		"all-namespaces",
		"A",
		false,
		"If present, list requested object(s) across all namespaces",
	)

	return cmd
}

func runPolicyShowProtectionCmd(opts *policyShowProtectionOptions) func(cmd *cobra.Command, args []string) error {
	return func(cmd *cobra.Command, _ []string) error {
		return withRuntimeEnforcerAndCoreClient(cmd, &opts.commonOptions, func(
			ctx context.Context,
			securityClient securityclient.SecurityV1alpha1Interface,
			coreClient corev1client.CoreV1Interface,
		) error {
			return runPolicyShowProtection(ctx, securityClient, coreClient, opts, opts.ioStreams.Out)
		})
	}
}

func runPolicyShowProtection(
	ctx context.Context,
	securityClient securityclient.SecurityV1alpha1Interface,
	coreClient corev1client.CoreV1Interface,
	opts *policyShowProtectionOptions,
	out io.Writer,
) error {
	rows, err := collectPolicyProtectionRows(ctx, securityClient, coreClient, opts)
	if err != nil {
		return err
	}
	return renderPolicyProtection(opts.Output, out, rows)
}

func collectPolicyProtectionRows(
	ctx context.Context,
	securityClient securityclient.SecurityV1alpha1Interface,
	coreClient corev1client.CoreV1Interface,
	opts *policyShowProtectionOptions,
) ([]workloadProtectionRow, error) {
	// - If the user doesn't specify a namespace, use the current namespace taken from the kubeconfig
	// - If the user specifies --namespace, use the specified namespace
	// - If the user specifies --all-namespaces, use the wildcard namespace
	namespace := opts.Namespace
	if opts.AllNamespaces {
		namespace = metav1.NamespaceAll
	}

	pods, err := coreClient.Pods(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list Pods in namespace %q: %w", namespace, err)
	}

	workloadPolicies, err := securityClient.WorkloadPolicies(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list WorkloadPolicies in namespace %q: %w", namespace, err)
	}

	return buildWorkloadProtectionRows(pods.Items, workloadPolicies.Items), nil
}

func buildWorkloadProtectionRows(
	pods []corev1.Pod,
	workloadPolicies []v1alpha1.WorkloadPolicy,
) []workloadProtectionRow {
	// we need to use policy namespace+name to have a unique key.
	policyByNamespacedName := make(map[types.NamespacedName]v1alpha1.WorkloadPolicy, len(workloadPolicies))
	for _, policy := range workloadPolicies {
		policyByNamespacedName[types.NamespacedName{Namespace: policy.Namespace, Name: policy.Name}] = policy
	}

	rowsByKey := map[types.NamespacedName]workloadProtectionRow{}
	for _, pod := range pods {
		policyName := pod.Labels[v1alpha1.PolicyLabelKey]
		// if there is no policy label we don't consider the pod
		if policyName == "" {
			continue
		}

		workloadName, workloadKind, _ := podworkload.GetTruncatedWorkloadInfo(pod.Name, pod.Labels)
		workloadNamespacedName := types.NamespacedName{Namespace: pod.Namespace, Name: workloadName}

		// Deduplicate the workload name
		if _, ok := rowsByKey[workloadNamespacedName]; ok {
			continue
		}

		policyKey := types.NamespacedName{Namespace: pod.Namespace, Name: policyName}
		policy, exists := policyByNamespacedName[policyKey]

		row := workloadProtectionRow{
			Workload: workloadNamespacedName.String(),
			Kind:     workloadKind.String(),
			Policy:   policyName,
			Mode:     unknownMode,
			Status:   missingStatus,
		}

		if exists {
			row.Mode = modeToUpper(policy.Spec.Mode)
			row.Status = string(policy.Status.Phase)
		}

		rowsByKey[workloadNamespacedName] = row
	}

	// sort them to always print the output in the same order
	rows := make([]workloadProtectionRow, 0, len(rowsByKey))
	for _, row := range rowsByKey {
		rows = append(rows, row)
	}

	slices.SortFunc(rows, func(a, b workloadProtectionRow) int {
		return strings.Compare(a.Workload, b.Workload)
	})

	return rows
}

func modeToUpper(mode string) string {
	switch mode {
	case policymode.MonitorString:
		return "Monitor"
	case policymode.ProtectString:
		return "Protect"
	default:
		panic(fmt.Sprintf("unknown mode %q", mode))
	}
}

func renderPolicyProtection(outMode string, out io.Writer, rows []workloadProtectionRow) error {
	switch outMode {
	case policyShowProtectionOutputTable:
		return renderPolicyProtectionTable(out, rows)
	case policyShowProtectionOutputJSON:
		return renderPolicyProtectionJSON(out, rows)
	default:
		return fmt.Errorf("invalid output %q, expected %q or %q",
			outMode,
			policyShowProtectionOutputTable,
			policyShowProtectionOutputJSON,
		)
	}
}

func renderPolicyProtectionTable(out io.Writer, rows []workloadProtectionRow) error {
	if len(rows) == 0 {
		fmt.Fprintln(out, "No workloads protected by a policy")
		return nil
	}
	printer := printers.NewTablePrinter(printers.PrintOptions{})
	table := &metav1.Table{
		ColumnDefinitions: []metav1.TableColumnDefinition{
			{Name: "WORKLOAD", Type: "string", Format: "name", Description: "Workload name"},
			{Name: "KIND", Type: "string", Description: "Workload kind"},
			{Name: "POLICY", Type: "string", Description: "Associated WorkloadPolicy"},
			{Name: "MODE", Type: "string", Description: "WorkloadPolicy mode"},
			{Name: "STATUS", Type: "string", Description: "WorkloadPolicy status"},
		},
		Rows: make([]metav1.TableRow, 0, len(rows)),
	}

	for _, row := range rows {
		table.Rows = append(table.Rows, metav1.TableRow{
			Cells: []any{row.Workload, row.Kind, row.Policy, row.Mode, row.Status},
		})
	}

	if err := printer.PrintObj(table, out); err != nil {
		return fmt.Errorf("failed to write table output: %w", err)
	}

	return nil
}

func renderPolicyProtectionJSON(out io.Writer, rows []workloadProtectionRow) error {
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")

	if err := encoder.Encode(rows); err != nil {
		return fmt.Errorf("failed to write JSON output: %w", err)
	}

	return nil
}
