{{/*
Expand the name of the chart.
*/}}
{{- define "runtime-enforcer.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "runtime-enforcer.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "runtime-enforcer.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "runtime-enforcer.labels" -}}
helm.sh/chart: {{ include "runtime-enforcer.chart" . }}
{{ include "runtime-enforcer.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "runtime-enforcer.selectorLabels" -}}
app.kubernetes.io/name: {{ include "runtime-enforcer.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "runtime-enforcer.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "runtime-enforcer.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Certificates helpers
*/}}
{{- define "runtime-enforcer.grpc.certDir" -}}
/etc/runtime-enforcer/certs
{{- end -}}
{{- define "runtime-enforcer.caIssuerName" -}}
{{ include "runtime-enforcer.fullname" . }}-ca
{{- end -}}
{{- define "runtime-enforcer.otelCollector.certDir" -}}
/etc/otel-collector/certs
{{- end -}}

{{/* Agent label selector string derived from agent pod labels */}}
{{- define "runtime-enforcer.agent.labelSelector" -}}
app.kubernetes.io/component: agent
{{ include "runtime-enforcer.selectorLabels" . }}
{{- end -}}

{{/* oci-hook install DaemonSet pod labels / selector */}}
{{- define "runtime-enforcer.ociHookInstall.labelSelector" -}}
app.kubernetes.io/component: oci-hook-install
{{ include "runtime-enforcer.selectorLabels" . }}
{{- end -}}

{{/*
Convert labels rendered as YAML (e.g. "k: v\nk2: v2") into a comma-separated selector string "k=v,k2=v2".
Usage:
  {{ include "runtime-enforcer.labelSelectorToString" (include "runtime-enforcer.agent.labelSelector" .) }}
*/}}
{{- define "runtime-enforcer.labelSelectorToString" -}}
{{- $yaml := . | default "" -}}
{{- $m := (fromYaml $yaml) | default dict -}}
{{- $keys := keys $m | sortAlpha -}}
{{- $out := list -}}
{{- range $k := $keys -}}
  {{- $out = append $out (printf "%s=%v" $k (get $m $k)) -}}
{{- end -}}
{{- join "," $out -}}
{{- end -}}

{{/* Convenience: agent selector string */}}
{{- define "runtime-enforcer.agent.labelSelectorString" -}}
{{- include "runtime-enforcer.labelSelectorToString" (include "runtime-enforcer.agent.labelSelector" .) -}}
{{- end -}}

{{/* Host + container directory for OCI socket and oci-hook binary (see .Values.ociHook.path). */}}
{{- define "runtime-enforcer.ociHook.dir" -}}
{{- trimSuffix "/" .Values.ociHook.path -}}
{{- end -}}

{{- define "runtime-enforcer.ociHook.socket" -}}
{{- printf "%s/oci-hook.sock" (include "runtime-enforcer.ociHook.dir" .) -}}
{{- end -}}

{{- define "runtime-enforcer.ociHook.bin" -}}
{{- printf "%s/oci-hook" (include "runtime-enforcer.ociHook.dir" .) -}}
{{- end -}}
