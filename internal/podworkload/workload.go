package podworkload

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/kubewarden/runtime-enforcer/internal/types/workloadkind"
)

// final 8-10 digits.
var cronJobNameRegexp = regexp.MustCompile(`(.+)-\d{8,10}$`)

const (
	// known labels.
	podTemplateHashLabel = "pod-template-hash"
	oldJobNameLabel      = "job-name"
	newJobNameLabel      = "batch.kubernetes.io/job-name"
	statefulsetLabel     = "statefulset.kubernetes.io/pod-name"
	daemonsetLabel       = "controller-revision-hash"
	// we want to keep the suffix within 5 chars to avoid exceeding the 63 character limit.
	truncatedSuffix = "-trnc"
	// k8s random suffix len of deployment/daemonset.
	randomSuffixLen = 5
	// we want to find at least 5 characters of the pod template hash to avoid false positives.
	minTemplateHashMatch = 5
)

func parseDeployment(podName, templateHash string) (string, workloadkind.Kind) {
	// Usually the pod-name for a pod managed by a deployment has the format:
	// pod-name: [deployment-name]-[hash]-[random]
	// But we need to take into account that the pod-name has a maximum length of 63 characters,
	// so if the name of the deployment is too long, it will be truncated.
	// Please note that the deployment shouldn't have as well more than 63 characters, but we still need some room for [hash]-[random].
	// Moreover k8s doesn't enforce any check so potentially the deployment name could be longer than 63 characters.
	//
	// Concrete examples:
	// 1. Regular case
	//    deployment-name: ubuntu-deployment-674bcc58f4-pwvps
	//    pod-name: ubuntu-deployment
	//
	// 2. 63 characters
	//    deployment-name: ubuntu-deploymentttttttttttttttttttttttttttttttttttttttttttttt
	//    pod-name: ubuntu-deploymenttttttttttttttttttttttttttttttttttttttttttq8fcg
	//    In this case we have just the final [random(q8fcg)] without the `-`. The name of the deployment is truncated.
	//
	// 3. 56 characters
	//    deployment-name: ubuntu-deploymentttttttttttttttttttttttttttttttttttttt-t
	//    pod-name: ubuntu-deploymentttttttttttttttttttttttttttttttttttttt-t-65fb8c
	//    In this case `-[hash]-[random]` are just collapsed into `-65fb8c` but the name is not truncated

	// first we trim the random suffix, we always have it.
	// Example:
	// from: ubuntu-deployment-674bcc58f4-pwvps
	// to: ubuntu-deployment-674bcc58f4-
	podPrefixWithPartialHash := podName[:len(podName)-randomSuffixLen]

	// we first try a match with the exactPattern, if we don't find it we will look for a partial match
	exactPattern := "-" + templateHash + "-"
	for i := len(exactPattern); i >= minTemplateHashMatch; i-- {
		targetPartialHash := exactPattern[:i]
		if strings.HasSuffix(podPrefixWithPartialHash, targetPartialHash) {
			return podPrefixWithPartialHash[:len(podPrefixWithPartialHash)-len(targetPartialHash)], workloadkind.Deployment
		}
	}

	// If we are not sure, we just keep the name without the random suffix and we add our truncated suffix.
	// it is possible we still have the `-` so we trim it.
	return strings.TrimSuffix(podPrefixWithPartialHash, "-") + truncatedSuffix, workloadkind.Deployment
}

func parseDaemonSet(podName string) (string, workloadkind.Kind) {
	// Usually the pod-name for a pod managed by a daemonset has the format:
	// pod-name: [daemonset-name]-[random-5chars]
	// But we need to take into account that the pod-name has a maximum length of 63 characters,
	// so if the name of the daemonset is too long, it will be truncated and the `-` will be omitted.
	//
	// Concrete examples:
	// 1. Regular case
	//    daemonset-name: ubuntu-daemonset
	//    pod-name: ubuntu-daemonset-6qq8v
	//
	// 2. Long case
	//    daemonset-name: ubuntu-daemonsetttttttttttttttttttttttttttttttttttttttttttttttttttt
	//    pod-name: ubuntu-daemonsettttttttttttttttttttttttttttttttttttttttttt6qq8v
	//    So the name of the daemonset is truncated and the `-` will be omitted.

	// we remove the suffix that is always present
	nameWithoutSuffix := podName[:len(podName)-randomSuffixLen]

	if before, ok := strings.CutSuffix(nameWithoutSuffix, "-"); ok {
		return before, workloadkind.DaemonSet
	}
	// if the `-` is not present, we consider the name as truncated, we add a suffix to signal it
	return nameWithoutSuffix + truncatedSuffix, workloadkind.DaemonSet
}

func parseJobCronJob(jobName string) (string, workloadkind.Kind) {
	m := cronJobNameRegexp.FindStringSubmatch(jobName)
	if len(m) == 2 { //nolint:mnd // m[0] is the full match, m[1] is the job name
		return m[1], workloadkind.CronJob
	}
	return jobName, workloadkind.Job
}

func parseStatefulSet(podName string) (string, workloadkind.Kind) {
	// pod-name: [statefulset-name]-[progressive-index]
	// the statefulset name has at most 63 characters, and the `-` cannot be omitted so its enough to just take the prefix
	lastDashIndex := strings.LastIndex(podName, "-")
	if lastDashIndex == -1 {
		panic(fmt.Sprintf("statefulset: missing last '-' in pod name '%s'", podName))
	}
	return podName[:lastDashIndex], workloadkind.StatefulSet
}

func getWorkloadInfo(podName string, labels map[string]string) (string, workloadkind.Kind) {
	// DEPLOYMENT
	// if a pod is created by a deployment it has the template hash label
	if hash, ok := labels[podTemplateHashLabel]; ok {
		return parseDeployment(podName, hash)
	}

	// STATEFULSET
	// if a pod is created by a statefulset it has the statefulset label
	if statefulPodName, ok := labels[statefulsetLabel]; ok {
		return parseStatefulSet(statefulPodName)
	}

	// DAEMONSET
	// if a pod is created by a daemonset it has the controller revision hash label
	if _, ok := labels[daemonsetLabel]; ok {
		return parseDaemonSet(podName)
	}

	// CRONJOB/JOB
	// both have the `job-name`/`batch.kubernetes.io/job-name` label. To distinguish them we use the random generated suffix after the cronjob.
	// it's still possible there is a job with a really weird suffix that is not a cronjob, but for now we don't consider this case.
	if jobName, ok := labels[oldJobNameLabel]; ok {
		return parseJobCronJob(jobName)
	}
	if jobName, ok := labels[newJobNameLabel]; ok {
		return parseJobCronJob(jobName)
	}

	// Everything that is not a known workload type is considered a regular pod.

	return podName, workloadkind.Pod
}

// GetTruncatedWorkloadInfo returns the workload name, kind, and whether it was truncated.
func GetTruncatedWorkloadInfo(podName string, labels map[string]string) (string, workloadkind.Kind, bool) {
	workloadName, workloadKind := getWorkloadInfo(podName, labels)
	return workloadName, workloadKind, strings.HasSuffix(workloadName, truncatedSuffix)
}
