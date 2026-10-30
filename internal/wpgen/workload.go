package wpgen

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/kubewarden/runtime-enforcer/api/v1alpha1"
	"github.com/kubewarden/runtime-enforcer/internal/policydraft"
	"github.com/kubewarden/runtime-enforcer/internal/workloadparse"
)

const stdinFile = "-"

type workloadOptions struct {
	draftOptions
}

// draftedWorkload is a workload with the name of its policy.
type draftedWorkload struct {
	workloadparse.Workload

	PolicyName string
	// LabelPresent is true when the pod template already has the policy label.
	LabelPresent bool
}

func newWorkloadCmd(g *globalOptions) *cobra.Command {
	opts := &workloadOptions{}

	cmd := &cobra.Command{
		Use:   "workload FILE",
		Short: "Draft one WorkloadPolicy per workload of a manifest file",
		Long: `Draft one WorkloadPolicy per workload of a manifest file.

FILE has one or more YAML or JSON documents. Use "-" to read from standard
input. wpgen reads these kinds: Deployment, ReplicaSet, DaemonSet,
StatefulSet, Job and CronJob. It skips the other documents, and also bare
pods, because the learn phase of runtime-enforcer does not cover them.

Each policy has one entry per container and init container. Each image is
scanned once, also when more containers use it. As with wpgen image, the
policy allows the programs and the scripts of the image, and skips the
shared libraries and the other files, unless you use --include-libraries or
--include-unknown.

The policy name is the value of the runtimeenforcer.kubewarden.io/policy
label of the pod template. When the label is not there, the name is
<short kind>-<workload name>, for example deploy-nginx, as for the
WorkloadPolicyProposal that the learn phase creates. The policy has the
namespace of the workload. When the workload has no namespace, the policy
has none either, so that "kubectl apply -n" puts both in the same namespace.

The policies go to standard output. Messages go to standard error.`,
		Example: `  # Draft the policies of the workloads in a file
  wpgen workload ./deploy/nginx.yaml

  # Draft the policies of a Helm chart
  helm template my-release ./chart | wpgen workload -`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runWorkload(cmd.Context(), args[0], opts, newContextReader(cmd.Context(), cmd.InOrStdin()),
				g.streams(cmd.OutOrStdout(), cmd.ErrOrStderr()))
		},
	}

	opts.addFlags(cmd.Flags())

	return cmd
}

func runWorkload(
	ctx context.Context,
	file string,
	opts *workloadOptions,
	stdin io.Reader,
	s streams,
) error {
	if err := errors.Join(opts.validate()...); err != nil {
		return err
	}

	workloads, err := readWorkloads(file, stdin, s.err)
	if err != nil {
		return err
	}

	// Find the policy names before the images are loaded: a pull can take a
	// long time.
	drafted, err := draftWorkloads(workloads)
	if err != nil {
		return err
	}

	scanned := map[string]*scannedImage{}
	for _, w := range drafted {
		for _, c := range w.Containers {
			if _, done := scanned[c.Image]; done {
				continue
			}
			if scanned[c.Image], err = scanImage(ctx, c.Image, &opts.scanOptions, nil, s.err); err != nil {
				return err
			}
		}
	}

	policies := make([]*v1alpha1.WorkloadPolicy, 0, len(drafted))
	for _, w := range drafted {
		executables := make(map[string][]string, len(w.Containers))
		for _, c := range w.Containers {
			executables[c.Name] = scanned[c.Image].Executables
		}
		policy, newErr := policydraft.New(w.PolicyName, w.Namespace, opts.Mode, executables)
		if newErr != nil {
			return newErr
		}
		policies = append(policies, policy)
	}
	s.separate()
	if err = policydraft.EncodeAll(s.out, policies, opts.Output); err != nil {
		return err
	}

	for _, w := range drafted {
		printWorkloadSummary(s.err, s.errPainter, w, scanned, opts.WarnThreshold)
	}
	return nil
}

func readWorkloads(file string, stdin io.Reader, stderr io.Writer) ([]workloadparse.Workload, error) {
	r := stdin
	if file != stdinFile {
		f, err := os.Open(file)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		r = f
	}

	workloads, skipped, err := workloadparse.Parse(r)
	if err != nil {
		return nil, fmt.Errorf("cannot read %s: %w", file, err)
	}
	for _, s := range skipped {
		fmt.Fprintf(stderr, "Skipping %s %q (%s): %s\n", s.Kind, s.Name, s.APIVersion, s.Reason)
	}
	if len(workloads) == 0 {
		return nil, fmt.Errorf("no supported workload found in %s", file)
	}
	return workloads, nil
}

// draftWorkloads finds the policy name of each workload. It returns an error
// when two workloads of the same namespace map to the same policy, because
// the second policy replaces the first one when applied.
func draftWorkloads(workloads []workloadparse.Workload) ([]draftedWorkload, error) {
	drafted := make([]draftedWorkload, 0, len(workloads))
	owners := map[string]string{}

	for _, w := range workloads {
		d := draftedWorkload{Workload: w}
		d.PolicyName, d.LabelPresent = w.PodLabels[v1alpha1.PolicyLabelKey]
		if !d.LabelPresent {
			shortName, err := w.Kind.ShortName()
			if err != nil {
				return nil, err
			}
			d.PolicyName = shortName + "-" + w.Name
		}
		if err := validatePolicyName(d.PolicyName); err != nil {
			return nil, fmt.Errorf("%s %q: %w", w.Kind, w.Name, err)
		}

		owner := fmt.Sprintf("%s %q", w.Kind, w.Name)
		key := w.Namespace + "/" + d.PolicyName
		if other, found := owners[key]; found {
			return nil, fmt.Errorf("%s and %s both use the policy %q in the same namespace, "+
				"give them different %s labels", other, owner, d.PolicyName, v1alpha1.PolicyLabelKey)
		}
		owners[key] = owner

		drafted = append(drafted, d)
	}
	return drafted, nil
}

func printWorkloadSummary(
	w io.Writer,
	p painter,
	d draftedWorkload,
	scanned map[string]*scannedImage,
	warnThreshold int,
) {
	namespace := d.Namespace
	if namespace == "" {
		namespace = "<none>"
	}
	fmt.Fprintf(w, "\n%s %s (namespace %s), policy %s\n", d.Kind, d.Name, namespace, d.PolicyName)

	containers := make([]draftedContainer, 0, len(d.Containers))
	for _, c := range d.Containers {
		containers = append(containers, draftedContainer{
			Label:   containerLabel(c.Name, c.Init),
			Image:   c.Image,
			Scanned: scanned[c.Image],
		})
	}
	printDraftSummary(w, p, containers, warnThreshold)

	if d.LabelPresent {
		fmt.Fprintf(w, "\nThe pod template already has the label %s: %s\n", v1alpha1.PolicyLabelKey, d.PolicyName)
		return
	}
	fmt.Fprintf(w, "\nAdd this label to the pod template of %s %s:\n  %s: %s\n",
		d.Kind, d.Name, v1alpha1.PolicyLabelKey, d.PolicyName)
}
