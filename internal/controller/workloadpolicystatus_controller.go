package controller

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/go-logr/logr"
	securityv1alpha1 "github.com/neuvector/runtime-enforcer/api/v1alpha1"
	"github.com/neuvector/runtime-enforcer/internal/defaults"
	pb "github.com/neuvector/runtime-enforcer/proto/policyproxy/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

const (
	// this to avoid a too large list in case of many node failures.
	nodeFailuresMaxLen = 10
	agentClientTimeout = 5 * time.Second
	keyValueParts      = 2
)

type agentClient struct {
	conn   *grpc.ClientConn
	client pb.PolicyProxyServiceClient
}

// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch
// +kubebuilder:rbac:groups=security.rancher.io,resources=workloadsecuritypolicies/status,verbs=get;update;patch

// WorkloadPolicyStatusReconciler reconciles a WorkloadPolicy status.
type WorkloadPolicyStatusReconciler struct {
	client.Client

	conns                 map[string]*agentClient
	policyProxyServerPort string
	log                   logr.Logger
	updateInterval        time.Duration
	daemonNamespace       string
	daemonLabelSelector   map[string]string
}

func NewWorkloadPolicyStatusReconciler(c client.Client) (*WorkloadPolicyStatusReconciler, error) {
	// Get Proxy gRPC address
	addr := os.Getenv(defaults.PolicyProxyGRPCAddressEnvKey)
	if addr == "" {
		return nil, fmt.Errorf("environment variable '%s' is not set", defaults.PolicyProxyGRPCAddressEnvKey)
	}

	// Search `:` inside the addr to extract the port
	index := strings.LastIndex(addr, ":")
	if index == -1 || index == len(addr)-1 {
		return nil, fmt.Errorf("invalid gRPC address format: %s", addr)
	}

	// Get update interval
	updateInterval, err := time.ParseDuration(os.Getenv(defaults.WPSControllerUpdateIntervalKey))
	if err != nil {
		return nil, fmt.Errorf(
			"invalid duration format for status-update-interval: %s. Error: %w",
			os.Getenv(defaults.WPSControllerUpdateIntervalKey),
			err,
		)
	}

	// Get daemon namespace
	daemonNamespace := os.Getenv(defaults.WPSControllerDaemonNamespace)
	if daemonNamespace == "" {
		return nil, fmt.Errorf("environment variable '%s' is not set", defaults.WPSControllerDaemonNamespace)
	}

	// Get daemon label selector
	daemonLabelSelectorStr := os.Getenv(defaults.WPSControllerDaemonLabelSelector)
	if daemonLabelSelectorStr == "" {
		return nil, fmt.Errorf("environment variable '%s' is not set", defaults.WPSControllerDaemonLabelSelector)
	}

	daemonLabelSelector := make(map[string]string)
	labels := strings.Split(daemonLabelSelectorStr, ",")
	for _, label := range labels {
		parts := strings.Split(label, "=")
		if len(parts) != keyValueParts {
			return nil, fmt.Errorf("invalid label selector format: %s", daemonLabelSelectorStr)
		}
		daemonLabelSelector[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
	}

	return &WorkloadPolicyStatusReconciler{
		Client:                c,
		conns:                 make(map[string]*agentClient),
		policyProxyServerPort: addr[index+1:],
		updateInterval:        updateInterval,
		daemonNamespace:       daemonNamespace,
		daemonLabelSelector:   daemonLabelSelector,
	}, nil
}

func (r *WorkloadPolicyStatusReconciler) Reconcile(
	ctx context.Context,
	_ MockEvent,
) (ctrl.Result, error) {
	r.log = log.FromContext(ctx)

	// As first step, we list all WorkloadSecurityPolicies, if there are none, we can reschedule and exit early
	var wspList securityv1alpha1.WorkloadSecurityPolicyList
	if err := r.List(ctx, &wspList); err != nil {
		return ctrl.Result{}, err
	}

	if len(wspList.Items) == 0 {
		r.log.V(1).Info("No WorkloadSecurityPolicies found, retrying later")
		return ctrl.Result{RequeueAfter: r.updateInterval}, nil
	}

	// Get all pods with the agent label in the agent namespace
	var podList corev1.PodList
	if err := r.List(ctx, &podList,
		client.InNamespace(r.daemonNamespace),
		client.MatchingLabels(r.daemonLabelSelector),
	); err != nil {
		return ctrl.Result{}, err
	}

	r.log.V(1).Info("List pods", "numPods", len(podList.Items))
	if len(podList.Items) == 0 {
		// we should have a pod running the agent, so if we don't find any, we return an error
		return ctrl.Result{}, errors.New("no agent pods found")
	}

	// Cleanup of stale connections as first thing so that we don't indefinitely grow the map in case of failures
	active := make(map[string]struct{})
	for _, pod := range podList.Items {
		// We also check there are no 2 pods on the same node! This should never happen if we correctly use the DaemonSet labels
		if _, ok := active[pod.Spec.NodeName]; ok {
			return ctrl.Result{}, fmt.Errorf("duplicate agent pod found on node %s", pod.Spec.NodeName)
		}
		active[pod.Spec.NodeName] = struct{}{}
	}
	r.gcStaleConnections(active)

	nodePoliciesList := make(map[string]map[string]*pb.PolicyStatus, len(podList.Items))

	// For each pod, we try to get the policies status
	for _, pod := range podList.Items {
		// if one of the pods is not ready we should retry later
		if !isPodReady(&pod) {
			r.log.Info("Pod not ready, retrying later", "pod", pod.Name)
			return ctrl.Result{RequeueAfter: r.updateInterval}, nil
		}

		policies, err := r.getPodPoliciesStatus(ctx, &pod)
		if err != nil {
			return ctrl.Result{}, err
		}

		if len(policies) == 0 {
			// if there are no policies for this pod, we cannot do anything
			r.log.Info("No pod policies found, retrying later", "pod", pod.Name)
			return ctrl.Result{RequeueAfter: r.updateInterval}, nil
		}

		nodePoliciesList[pod.Spec.NodeName] = policies
	}

	// Now we iterate over all WSPs and update their status based on the collected policies status from the agents
	for _, wsp := range wspList.Items {
		err := r.processWorkloadPolicy(ctx, &wsp, nodePoliciesList)
		if err != nil {
			r.log.Error(
				err,
				"failed to process workload security policy",
				"policy",
				fmt.Sprintf("%s/%s", wsp.Namespace, wsp.Name),
			)
		}
	}

	return ctrl.Result{RequeueAfter: r.updateInterval}, nil
}

func newConnectionToPod(pod *corev1.Pod, port string) (*agentClient, error) {
	if pod.Status.PodIP == "" {
		return nil, fmt.Errorf("pod %s has no IP yet", pod.Name)
	}

	host := net.JoinHostPort(pod.Status.PodIP, port)
	conn, err := grpc.NewClient(host,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, fmt.Errorf("grpc dial failed host %s: %w", host, err)
	}

	return &agentClient{
		conn:   conn,
		client: pb.NewPolicyProxyServiceClient(conn),
	}, nil
}

func (r *WorkloadPolicyStatusReconciler) getPodPoliciesStatus(
	ctx context.Context,
	pod *corev1.Pod,
) (map[string]*pb.PolicyStatus, error) {
	// Check if we need to create a new connection or reuse an existing one
	agentClient, ok := r.conns[pod.Spec.NodeName]
	if !ok {
		c, err := newConnectionToPod(pod, r.policyProxyServerPort)
		if err != nil {
			return nil, fmt.Errorf("failed to create connection to pod %s: %w", pod.Name, err)
		}
		r.conns[pod.Spec.NodeName] = c
		agentClient = c
	}

	timeoutCtx, timeoutCancel := context.WithTimeout(ctx, agentClientTimeout)
	defer timeoutCancel()

	resp, err := agentClient.client.ListPoliciesStatus(timeoutCtx, &pb.ListPoliciesStatusRequest{})
	if err != nil {
		return nil, fmt.Errorf("failed to list policies status for pod %s: %w", pod.Name, err)
	}

	return resp.GetPolicies(), nil
}

func (r *WorkloadPolicyStatusReconciler) processWorkloadPolicy(
	ctx context.Context,
	wsp *securityv1alpha1.WorkloadSecurityPolicy,
	nodePoliciesList map[string]map[string]*pb.PolicyStatus,
) error {
	// The Tetragon tracing policy should have the same name as the WSP and be in the same namespace
	key := fmt.Sprintf("%s/%s", wsp.Name, wsp.Namespace)

	nodeFailures := make([]string, 0, nodeFailuresMaxLen)

	for nodeName, policies := range nodePoliciesList {
		policyStatus, ok := policies[key]
		if !ok {
			// we miss the status for this policy on this node, we skip this wsp
			return nil
		}
		if policyStatus == nil {
			return fmt.Errorf("nil policy status for policy %s on node %s", key, nodeName)
		}
		switch policyStatus.GetState() {
		case pb.TracingPolicyState_TP_STATE_UNKNOWN:
		case pb.TracingPolicyState_TP_STATE_LOADING:
		case pb.TracingPolicyState_TP_STATE_UNLOADING:
			// the policy is in a transient state, we can update the status to Pending
			return r.updateWorkloadPolicyStatus(
				ctx,
				wsp,
				securityv1alpha1.PendingState,
				"PolicyTransient",
				fmt.Sprintf(
					"Policy %s on node %s is in transient state %s",
					key,
					nodeName,
					policyStatus.GetState().String(),
				),
			)
		case pb.TracingPolicyState_TP_STATE_ENABLED:
			// all good, continue to the next node
			continue
		case pb.TracingPolicyState_TP_STATE_DISABLED,
			pb.TracingPolicyState_TP_STATE_LOAD_ERROR,
			pb.TracingPolicyState_TP_STATE_ERROR:
			// also DISABLED is considered a failure for our purposes since nobody should disable a policy manually
			if len(nodeFailures) < nodeFailuresMaxLen {
				nodeFailures = append(nodeFailures, nodeName)
			} else if len(nodeFailures) == nodeFailuresMaxLen {
				nodeFailures = append(nodeFailures, "...")
			}
		default:
			panic(fmt.Sprintf("unhandled tracing policy state: %v", policyStatus.GetState()))
		}
	}

	// If we reach this point, it could mean 2 things:
	// - all nodes reported ENABLED -> we can set the WSP status to Deployed
	// - some nodes reported DISABLED/ERROR/LOAD_ERROR -> we set the WSP status to Degraded with the list of nodes
	if len(nodeFailures) == 0 {
		return r.updateWorkloadPolicyStatus(ctx, wsp, securityv1alpha1.DeployedState, "PolicyDeployed", "")
	}

	return r.updateWorkloadPolicyStatus(
		ctx,
		wsp,
		securityv1alpha1.FailedState,
		"PolicyFailed",
		fmt.Sprintf("Policy %s is not correctly deployed on the following nodes: %v", key, nodeFailures),
	)
}

func (r *WorkloadPolicyStatusReconciler) updateWorkloadPolicyStatus(
	ctx context.Context,
	policy *securityv1alpha1.WorkloadSecurityPolicy,
	ty securityv1alpha1.WorkloadSecurityPolicyState,
	reason string,
	message string,
) error {
	newPolicy := policy.DeepCopy()

	// We are in the same state, no need to update
	if newPolicy.Status.State == string(ty) {
		r.log.V(1).
			Info("wp status unchanged, skipping update", "policy", fmt.Sprintf("%s/%s", policy.Namespace, policy.Name), "state", ty)
		return nil
	}

	newPolicy.Status.ObservedGeneration = newPolicy.Generation
	newPolicy.Status.State = string(ty)
	newPolicy.Status.Conditions = append(newPolicy.Status.Conditions, metav1.Condition{
		Type:               string(ty),
		Status:             "True",
		Reason:             reason,
		Message:            message,
		LastTransitionTime: metav1.Now(),
	})
	r.log.V(1).Info("wp status updated", "policy", fmt.Sprintf("%s/%s", policy.Namespace, policy.Name), "new state", ty)
	return r.Status().Update(ctx, newPolicy)
}

func (r *WorkloadPolicyStatusReconciler) gcStaleConnections(activePods map[string]struct{}) {
	for nodeName, c := range r.conns {
		if _, ok := activePods[nodeName]; ok {
			continue
		}
		_ = c.conn.Close()
		delete(r.conns, nodeName)
	}
}

func isPodReady(pod *corev1.Pod) bool {
	for _, cond := range pod.Status.Conditions {
		if cond.Type == corev1.PodReady && cond.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}

// SetupWithManager sets up the controller with the Manager.
func (r *WorkloadPolicyStatusReconciler) SetupWithManager(mgr ctrl.Manager) error {
	startChan := make(chan event.TypedGenericEvent[MockEvent])
	err := builder.TypedControllerManagedBy[MockEvent](mgr).
		Named("workloadpolicystatus").
		WatchesRawSource(
			source.TypedChannel(
				startChan,
				&MockEventHandler{},
			)).Complete(r)

	// Send a first event to kickstart the reconciliation loop. The controller will requeue itself after each reconciliation.
	go func() {
		time.Sleep(1 * time.Second)
		startChan <- event.TypedGenericEvent[MockEvent]{Object: MockEvent{}}
		close(startChan)
	}()
	return err
}
