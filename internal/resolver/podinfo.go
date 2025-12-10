package resolver

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/neuvector/runtime-enforcer/internal/labels"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var cronJobNameRegexp = regexp.MustCompile(`(.+)-\d{8,10}$`)

const (
	workloadTypePod                   = "Pod"
	workloadTypeDeployment            = "Deployment"
	workloadTypeStatefulSet           = "StatefulSet"
	workloadTypeDaemonSet             = "DaemonSet"
	workloadTypeReplicaSet            = "ReplicaSet"
	workloadTypeDeploymentConfig      = "DeploymentConfig"
	workloadTypeJob                   = "Job"
	workloadTypeCronJob               = "CronJob"
	workloadTypeReplicationController = "ReplicationController"

	podTemplateHashLabel  = "pod-template-hash"
	deploymentConfigLabel = "deploymentconfig"
)

type podInfo struct {
	// this should become a separate type if needed
	podID        string
	namespace    string
	name         string
	workloadName string
	workloadType string
	labels       labels.Labels
}

func getPodInfo(pod *corev1.Pod) *podInfo {
	if pod == nil {
		return nil
	}

	info := &podInfo{
		podID:        string(pod.UID),
		namespace:    pod.Namespace,
		name:         pod.Name,
		workloadName: pod.Name,
		workloadType: workloadTypePod,
		labels:       pod.Labels,
	}

	if len(pod.GenerateName) == 0 {
		// We assume this is a single pod, not part of a deployment, statefulset, etc.
		return info
	}

	// if the pod name was generated (or is scheduled for generation), we can begin an investigation into the controlling reference for the pod.
	var controllerRef metav1.OwnerReference
	controllerFound := false
	for _, ref := range pod.GetOwnerReferences() {
		if ref.Controller != nil && *ref.Controller {
			controllerRef = ref
			controllerFound = true
			break
		}
	}

	if !controllerFound {
		// todo!: for now if there is the generated name but the controller is not found we return the pod workloadType, but not sure if this is the best approach. We need to understand in which cases this can happen in practice.
		return info
	}

	switch {
	// heuristic for deployment detection
	case controllerRef.Kind == workloadTypeReplicaSet &&
		pod.Labels[podTemplateHashLabel] != "" &&
		strings.HasSuffix(controllerRef.Name, pod.Labels[podTemplateHashLabel]):
		name := strings.TrimSuffix(controllerRef.Name, "-"+pod.Labels[podTemplateHashLabel])
		info.workloadType = workloadTypeDeployment
		info.workloadName = name
	case controllerRef.Kind == workloadTypeReplicationController &&
		pod.Labels[deploymentConfigLabel] != "":

		// If the pod is controlled by the replication controller, which is created by the DeploymentConfig resource in
		// Openshift platform, set the deploy name to the deployment config's name, and the kind to 'DeploymentConfig'.
		//
		//nolint: lll // long regex, kept on a single line for readability when compared with the cgroup path format
		// For DeploymentConfig details, refer to
		// https://docs.openshift.com/container-platform/4.1/applications/deployments/what-deployments-are.html#deployments-and-deploymentconfigs_what-deployments-are
		//
		// For the reference to the pod label 'deploymentconfig', refer to
		// https://github.com/openshift/library-go/blob/7a65fdb398e28782ee1650959a5e0419121e97ae/pkg/apps/appsutil/const.go#L25
		info.workloadName = pod.Labels[deploymentConfigLabel]
		info.workloadType = workloadTypeDeploymentConfig
	case controllerRef.Kind == workloadTypeJob:
		// If job name suffixed with `-<digit-timestamp>`, where the length of digit timestamp is 8~10,
		// trim the suffix and set kind to cron job.
		if jn := cronJobNameRegexp.FindStringSubmatch(controllerRef.Name); len(jn) == 2 {
			info.workloadName = jn[1]
			info.workloadType = workloadTypeCronJob
		}
	default:
		info.workloadType = controllerRef.Kind
		info.workloadName = controllerRef.Name
	}

	return info
}

type KubeInfo struct {
	PodID         string
	PodName       string
	Namespace     string
	ContainerName string
	WorkloadName  string
	WorkloadType  string
	ContainerID   string
}

var (
	// ErrMissingPodUID is returned when no Pod UID could be found for the given cgroup ID.
	ErrMissingPodUID = errors.New("missing pod UID for cgroup ID")

	// ErrMissingPodInfo is returned when the Pod UID was found, but
	// the detailed Pod information is missing.
	ErrMissingPodInfo = errors.New("missing pod info for found pod ID")
)

func (r *Resolver) GetKubeInfo(cgID CgroupID) (*KubeInfo, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	podID, ok := r.cgroupIDToPodID[cgID]
	if !ok {
		return nil, fmt.Errorf("%w: %d", ErrMissingPodUID, cgID)
	}

	pod, ok := r.podCache[podID]
	if !ok {
		return nil, fmt.Errorf("%w: %s (cgroup ID %d)", ErrMissingPodInfo, podID, cgID)
	}

	containerName := "not-found"
	containerID := "not-found"
	for cID, info := range pod.containers {
		if cgID == info.cgID {
			containerName = info.name
			containerID = cID
			break
		}
	}

	return &KubeInfo{
		PodID:         podID,
		PodName:       pod.info.name,
		Namespace:     pod.info.namespace,
		ContainerName: containerName,
		WorkloadName:  pod.info.workloadName,
		WorkloadType:  pod.info.workloadType,
		ContainerID:   containerID,
	}, nil
}
