package e2e_test

import (
	"bytes"
	"context"
	"os/exec"
	"strconv"
	"testing"
	"time"

	"github.com/kubewarden/runtime-enforcer/api/v1alpha1"
	"github.com/kubewarden/runtime-enforcer/internal/types/policymode"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/e2e-framework/klient/k8s"
	"sigs.k8s.io/e2e-framework/klient/wait"
	"sigs.k8s.io/e2e-framework/klient/wait/conditions"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"
	"sigs.k8s.io/e2e-framework/pkg/types"
)

func getKubectlPluginSmokeTest() types.Feature {
	proposalName := "deploy-opensuse-deployment"
	policyName := proposalName // Policy gets the same name as proposal
	containerName := "opensuse"

	return features.New("kubectl plugin: proposal promote").
		Setup(SetupSharedK8sClient).
		Setup(SetupTestNamespace).
		Setup(func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
			// Create deployment to trigger learning
			createAndWaitOpensuseDeployment(ctx, t)
			return ctx
		}).
		Assess("required resources become available", IfRequiredResourcesAreCreated).
		Assess("the workload proposal is created successfully for the opensuse pod",
			func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
				r := getClient(ctx)

				proposal := v1alpha1.WorkloadPolicyProposal{
					Name:      proposalName,
					Namespace: getNamespace(ctx),
				}

				// Wait for proposal to be created
				err := wait.For(conditions.New(r).ResourceMatch(
					&proposal,
					func(object k8s.Object) bool {
						obj := object.(*v1alpha1.WorkloadPolicyProposal)
						if len(obj.OwnerReferences) == 0 {
							return false
						}
						if obj.OwnerReferences[0].Name == opensuseDeploymentName &&
							obj.OwnerReferences[0].Kind == "Deployment" {
							return true
						}
						return false
					}),
					wait.WithTimeout(defaultOperationTimeout),
				)
				require.NoError(t, err)

				return context.WithValue(ctx, key("group"), proposal.Name)
			}).
		Assess("the running process is learned",
			func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
				id := ctx.Value(key("group")).(string)
				r := getClient(ctx)

				t.Log("waiting for policy proposal to be created: ", id)

				proposal := v1alpha1.WorkloadPolicyProposal{
					Name:      id,
					Namespace: getNamespace(ctx),
				}

				// There are two categories of processes to be learned:
				// 1. /usr/bin/bash: the container entrypoint.
				// 2. /usr/bin/sleep & /usr/bin/ls: the commands the container executes
				t.Log("waiting for processes to be learned")

				err := wait.For(conditions.New(r).ResourceMatch(
					&proposal,
					func(_ k8s.Object) bool {
						rules, ok := proposal.Spec.RulesByContainer["opensuse"]

						if !ok {
							return false
						}

						return verifyOpensuseLearnedProcesses(rules.Executables.Allowed)
					}),
					wait.WithTimeout(defaultOperationTimeout),
				)
				require.NoError(t, err)

				return context.WithValue(ctx, key("proposal"), &proposal)
			}).
		Assess("kubectl plugin promotes proposal successfully",
			func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
				temp := "./../../bin/kubectl-runtime_enforcer proposal promote " + proposalName + " --namespace " + getNamespace(
					ctx,
				)
				cmd := exec.Command("bash", "-c", temp)
				var stdout, stderr bytes.Buffer
				cmd.Stdout = &stdout
				cmd.Stderr = &stderr
				err := cmd.Run()

				require.NoError(t, err, "plugin command should succeed")
				t.Logf("stdout: %s", stdout.String())
				t.Logf("stderr: %s", stderr.String())

				assert.Contains(t, stdout.String(), "Promoted WorkloadPolicyProposal")
				assert.Contains(t, stdout.String(), proposalName)
				assert.Contains(t, stdout.String(), "WorkloadPolicy")
				assert.Contains(t, stdout.String(), "has been created")

				return ctx
			}).
		Assess("WorkloadPolicy was created in monitor mode",
			func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
				r := getClient(ctx)

				policy := v1alpha1.WorkloadPolicy{
					Name:      policyName,
					Namespace: getNamespace(ctx),
				}

				err := wait.For(conditions.New(r).ResourceMatch(&policy, func(_ k8s.Object) bool {
					return policy.Spec.Mode == policymode.MonitorString
				}), wait.WithTimeout(10*time.Second))
				require.NoError(t, err)

				assert.Equal(t, policymode.MonitorString, policy.Spec.Mode)
				assert.NotNil(t, policy.Spec.RulesByContainer["opensuse"])

				return ctx
			}).
		Assess("WorkloadPolicyProposal was deleted after promotion",
			func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
				r := getClient(ctx)

				proposal := v1alpha1.WorkloadPolicyProposal{
					Name:      proposalName,
					Namespace: getNamespace(ctx),
				}

				err := wait.For(
					conditions.New(r).ResourceDeleted(&proposal),
					wait.WithTimeout(defaultOperationTimeout),
				)
				require.NoError(t, err, "proposal should be deleted after promotion")

				return ctx
			}).
		Assess("kubectl plugin switches mode to protect",
			func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
				temp := "./../../bin/kubectl-runtime_enforcer policy protect " + policyName + " --namespace " + getNamespace(
					ctx,
				)
				cmd := exec.Command("bash", "-c", temp)
				var stdout, stderr bytes.Buffer
				cmd.Stdout = &stdout
				cmd.Stderr = &stderr
				err := cmd.Run()

				require.NoError(t, err, "plugin command should succeed")
				t.Logf("stdout: %s", stdout.String())
				t.Logf("stderr: %s", stderr.String())

				assert.Contains(t, stdout.String(), "Successfully set WorkloadPolicy")
				assert.Contains(t, stdout.String(), policyName)
				assert.Contains(t, stdout.String(), "protect")

				// Verify the policy mode changed
				r := getClient(ctx)
				policy := v1alpha1.WorkloadPolicy{
					Name:      policyName,
					Namespace: getNamespace(ctx),
				}
				err = r.Get(ctx, policyName, getNamespace(ctx), &policy)
				require.NoError(t, err)
				assert.Equal(t, policymode.ProtectString, policy.Spec.Mode)

				return ctx
			}).
		Assess("kubectl plugin switches mode back to monitor",
			func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
				temp := "./../../bin/kubectl-runtime_enforcer policy monitor " + policyName + " --namespace " + getNamespace(
					ctx,
				)
				cmd := exec.Command("bash", "-c", temp)
				var stdout, stderr bytes.Buffer
				cmd.Stdout = &stdout
				cmd.Stderr = &stderr
				err := cmd.Run()

				require.NoError(t, err, "plugin command should succeed")
				t.Logf("stdout: %s", stdout.String())
				t.Logf("stderr: %s", stderr.String())
				assert.Contains(t, stdout.String(), "Successfully set WorkloadPolicy")
				assert.Contains(t, stdout.String(), "monitor")

				// Verify the policy mode changed back
				r := getClient(ctx)
				policy := v1alpha1.WorkloadPolicy{
					Name:      policyName,
					Namespace: getNamespace(ctx),
				}
				err = r.Get(ctx, policyName, getNamespace(ctx), &policy)
				require.NoError(t, err)
				assert.Equal(t, policymode.MonitorString, policy.Spec.Mode)

				return ctx
			}).
		Assess("kubectl plugin allows new executables",
			func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
				temp := "./../../bin/kubectl-runtime_enforcer policy allow " + policyName + " " + containerName + " /usr/bin/cat /usr/bin/grep " + " --namespace " + getNamespace(
					ctx,
				)
				cmd := exec.Command("bash", "-c", temp)
				var stdout, stderr bytes.Buffer
				cmd.Stdout = &stdout
				cmd.Stderr = &stderr
				err := cmd.Run()

				require.NoError(t, err, "plugin command should succeed")
				t.Logf("stdout: %s", stdout.String())
				t.Logf("stderr: %s", stderr.String())

				assert.Contains(t, stdout.String(), "Successfully updated executables")

				// Verify the executables were added
				r := getClient(ctx)
				policy := v1alpha1.WorkloadPolicy{
					Name:      policyName,
					Namespace: getNamespace(ctx),
				}
				err = r.Get(ctx, policyName, getNamespace(ctx), &policy)
				require.NoError(t, err, "plugin command should succeed")

				allowed := policy.Spec.RulesByContainer[containerName].Executables.Allowed
				assert.Contains(t, allowed, "/usr/bin/sleep")
				assert.Contains(t, allowed, "/usr/bin/ls")
				assert.Contains(t, allowed, "/usr/bin/bash")
				assert.Contains(t, allowed, "/usr/bin/cat")
				assert.Contains(t, allowed, "/usr/bin/grep")
				assert.Len(t, allowed, 5)

				return ctx
			}).
		Assess("kubectl plugin denies executables",
			func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
				temp := "./../../bin/kubectl-runtime_enforcer policy deny " + policyName + " " + containerName + " /usr/bin/grep /usr/bin/cat " + " --namespace " + getNamespace(
					ctx,
				)
				cmd := exec.Command("bash", "-c", temp)
				var stdout, stderr bytes.Buffer
				cmd.Stdout = &stdout
				cmd.Stderr = &stderr
				err := cmd.Run()

				require.NoError(t, err, "plugin command should succeed")
				t.Logf("stdout: %s", stdout.String())
				t.Logf("stderr: %s", stderr.String())

				assert.Contains(t, stdout.String(), "Successfully updated executables")

				// Verify the executables were removed
				r := getClient(ctx)
				policy := v1alpha1.WorkloadPolicy{
					Name:      policyName,
					Namespace: getNamespace(ctx),
				}
				err = r.Get(ctx, policyName, getNamespace(ctx), &policy)
				require.NoError(t, err)

				allowed := policy.Spec.RulesByContainer[containerName].Executables.Allowed
				assert.Contains(t, allowed, "/usr/bin/sleep")
				assert.Contains(t, allowed, "/usr/bin/ls")
				assert.Contains(t, allowed, "/usr/bin/bash")
				assert.NotContains(t, allowed, "/usr/bin/grep")
				assert.NotContains(t, allowed, "/usr/bin/cat")
				assert.Len(t, allowed, 3)

				return ctx
			}).
		Assess("kubectl plugin acknowledges a violation", assessKubectlPluginAck(policyName, containerName)).
		Teardown(func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
			deleteOpensuseDeployment(ctx, t)
			r := getClient(ctx)
			policy := v1alpha1.WorkloadPolicy{
				Name:      policyName,
				Namespace: getNamespace(ctx),
			}
			_ = r.Delete(ctx, &policy)
			return ctx
		}).Feature()
}

func assessKubectlPluginAck(policyName, containerName string) features.Func {
	return func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
		deleteOpensuseDeployment(ctx, t)
		createAndWaitOpensuseDeployment(ctx, t, withPolicy(policyName))
		podName, err := findOpensuseDeploymentPod(ctx)
		require.NoError(t, err)

		t.Log("executing disallowed command to trigger a violation")
		requireExecAllowedInCurrentNamespace(
			ctx,
			t,
			podName,
			containerName,
			[]string{"/usr/bin/sh", "-c", "/usr/bin/zypper refresh"},
		)

		r := getClient(ctx)
		policy := &v1alpha1.WorkloadPolicy{
			Name:      policyName,
			Namespace: getNamespace(ctx),
		}

		var violationID int64
		err = wait.For(conditions.New(r).ResourceMatch(policy, func(obj k8s.Object) bool {
			wp, ok := obj.(*v1alpha1.WorkloadPolicy)
			if !ok {
				return false
			}
			for _, v := range wp.Status.Violations {
				if v.ExecutablePath == "/usr/bin/zypper" && v.PodName == podName {
					violationID = v.ID
					return true
				}
			}
			return false
		}), wait.WithTimeout(defaultOperationTimeout))
		require.NoError(t, err, "violation should appear in WorkloadPolicy status")

		temp := "./../../bin/kubectl-runtime_enforcer policy ack " +
			policyName + " " + strconv.FormatInt(violationID, 10) +
			" --reason " + strconv.Quote("e2e kubectl plugin acknowledgement") +
			" --namespace " + getNamespace(ctx)
		cmd := exec.Command("bash", "-c", temp)
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		err = cmd.Run()

		require.NoError(t, err, "plugin command should succeed")
		t.Logf("stdout: %s", stdout.String())
		t.Logf("stderr: %s", stderr.String())

		assert.Contains(t, stdout.String(), "Successfully acknowledged violation")
		assert.Contains(t, stdout.String(), policyName)

		return ctx
	}
}
