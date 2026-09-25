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

{{/* runAsUser/runAsGroup/fsGroup. The image's gateway user and group are both
1001: any other value runs the pod as root (0) or as an identity that does not
own HOME, so it is refused at render time instead of failing in the cluster. */}}
{{- define "mcp-gateway.podIdentity" -}}
{{- range $k := list "runAsUser" "runAsGroup" "fsGroup" }}
{{- $v := index $.Values.podSecurityContext $k }}
{{- if ne (toString $v) "1001" }}
{{- fail (printf "podSecurityContext.%s must be 1001, the image's non-root gateway UID/GID; got %v%s" $k $v (ternary " (root)" "" (eq (toString $v) "0"))) }}
{{- end }}
{{ $k }}: 1001
{{- end }}
{{- end -}}
