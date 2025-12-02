package resolver

import (
	"regexp"
	"strings"

	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	workloadTypeUnknown               = "Unknown"
	workloadTypePod                   = "Pod"
	workloadTypeDeployment            = "Deployment"
	workloadTypeStatefulSet           = "StatefulSet"
	workloadTypeDaemonSet             = "DaemonSet"
	workloadTypeReplicaSet            = "ReplicaSet"
	workloadTypeDeploymentConfig      = "DeploymentConfig"
	workloadTypeJob                   = "Job"
	workloadTypeCronJob               = "CronJob"
	workloadTypeReplicationController = "ReplicationController"
)

type podInfo struct {
	namespace    string
	name         string
	workloadName string
	workloadType string
}

var cronJobNameRegexp = regexp.MustCompile(`(.+)-\d{8,10}$`)

func getPodInfo(pod *corev1.Pod) *podInfo {
	if pod == nil {
		return nil
	}

	info := &podInfo{
		namespace:    pod.Namespace,
		name:         pod.Name,
		workloadName: pod.Name,
		workloadType: "Pod",
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
		// todo!: no controller found; we can evaluate if we want to return the pod or zero out the workload info
		info.workloadName = ""
		info.workloadType = workloadTypeUnknown
		return info
	}

	// heuristic for deployment detection
	// todo!: verify this logic taken from tetragon
	switch {
	case controllerRef.Name == workloadTypeReplicaSet &&
		pod.Labels["pod-template-hash"] != "" &&
		strings.HasSuffix(controllerRef.Name, pod.Labels["pod-template-hash"]):

		name := strings.TrimSuffix(controllerRef.Name, "-"+pod.Labels["pod-template-hash"])
		info.workloadType = workloadTypeDeployment
		info.workloadName = name
	case controllerRef.Name == workloadTypeReplicationController &&
		pod.Labels["deploymentconfig"] != "":

		// If the pod is controlled by the replication controller, which is created by the DeploymentConfig resource in
		// Openshift platform, set the deploy name to the deployment config's name, and the kind to 'DeploymentConfig'.
		//
		//nolint: lll
		// For DeploymentConfig details, refer to
		// https://docs.openshift.com/container-platform/4.1/applications/deployments/what-deployments-are.html#deployments-and-deploymentconfigs_what-deployments-are
		//
		// For the reference to the pod label 'deploymentconfig', refer to
		// https://github.com/openshift/library-go/blob/7a65fdb398e28782ee1650959a5e0419121e97ae/pkg/apps/appsutil/const.go#L25
		info.workloadName = pod.Labels["deploymentconfig"]
		info.workloadType = workloadTypeDeploymentConfig
	case controllerRef.Name == workloadTypeJob:
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

func containerIDFromContainerStatus(c *v1.ContainerStatus) string {
	ret := c.ContainerID
	if idx := strings.Index(ret, "://"); idx != -1 {
		ret = ret[idx+3:]
	}
	return ret
}

func podForAllContainers(pod *v1.Pod, fn func(c *v1.ContainerStatus)) {
	run := func(s []v1.ContainerStatus) {
		for i := range s {
			if s[i].State.Running != nil {
				fn(&s[i])
			}
		}
	}

	run(pod.Status.InitContainerStatuses)
	run(pod.Status.ContainerStatuses)
	run(pod.Status.EphemeralContainerStatuses)
}

func podContainersIDs(pod *v1.Pod) map[ContainerID]ContainerName {
	ret := make(map[ContainerID]ContainerName)
	podForAllContainers(pod, func(c *v1.ContainerStatus) {
		id := containerIDFromContainerStatus(c)
		ret[id] = c.Name
	})
	return ret
}
