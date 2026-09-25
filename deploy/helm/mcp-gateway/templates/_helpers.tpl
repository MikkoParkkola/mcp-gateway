{{/* Common name + label helpers */}}
{{- define "mcp-gateway.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "mcp-gateway.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "mcp-gateway.labels" -}}
app.kubernetes.io/name: {{ include "mcp-gateway.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: mcp-gateway-enterprise
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
{{- end -}}

{{- define "mcp-gateway.selectorLabels" -}}
app.kubernetes.io/name: {{ include "mcp-gateway.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "mcp-gateway.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "mcp-gateway.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/* Resolve the image ref: digest wins over tag for immutability. */}}
{{- define "mcp-gateway.image" -}}
{{- $reg := .Values.image.registry -}}
{{- $repo := .Values.image.repository -}}
{{- if .Values.image.digest -}}
{{- printf "%s/%s@%s" $reg $repo .Values.image.digest -}}
{{- else -}}
{{- printf "%s/%s:%s" $reg $repo (.Values.image.tag | default .Chart.AppVersion) -}}
{{- end -}}
{{- end -}}

{{/* Per-process state (UPGRADING-4.0 §37): one sentence per holder that is on,
     or empty. The render guard (configmap.yaml) fails on it above one replica
     and the Deployment picks Recreate on it, so the two cannot disagree. The
     modern protocol is on unless config.server.modern_protocol is false; a
     `default true` would replace an explicit false. */}}
{{- define "mcp-gateway.perProcessState" -}}
{{- $cfg := .Values.config | default dict -}}
{{- $reasons := list -}}
{{- if dig "key_server" "enabled" false $cfg -}}
{{- $reasons = append $reasons "config.key_server.enabled keeps issued tokens and revocations in one process's InMemoryTokenStore; set replicaCount: 1." -}}
{{- end -}}
{{- if dig "accounts" "enabled" false $cfg -}}
{{- $reasons = append $reasons "config.accounts.enabled: managed custody (accounts.deployment: single_process) holds one process's store and keys; set replicaCount: 1." -}}
{{- end -}}
{{- if ne (toString (dig "server" "modern_protocol" true $cfg)) "false" -}}
{{- $reasons = append $reasons "config.server.modern_protocol (on unless set false) serves the tasks extension, and each pod has its own task store; set replicaCount: 1, or config.server.modern_protocol: false." -}}
{{- end -}}
{{- join " " $reasons -}}
{{- end -}}
