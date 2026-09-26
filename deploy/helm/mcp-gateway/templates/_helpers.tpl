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

{{/* The server.cleartext_http value the gateway config renders, or "" when
     none is rendered (mesh mode accepts no credential, so C3 does not apply). */}}
{{- define "mcp-gateway.cleartextHttp" -}}
{{- if eq .Values.auth.mode "credential" -}}
{{- .Values.server.cleartextHttp | default "cluster_internal" -}}
{{- end -}}
{{- end -}}

{{/*
D6: refuse to render an audit emptyDir that cannot hold the rotating log:
(retainSegments + 1) x maxSegmentBytes + a 1Mi reserve must fit in 90% of
sizeLimit. Quantities: plain bytes, or Ki/Mi/Gi/Ti, or k/M/G/T.
*/}}
{{- define "mcp-gateway.auditFitsVolume" -}}
{{- $q := toString .Values.audit.sizeLimit -}}
{{- $units := dict "Ki" 1024 "Mi" 1048576 "Gi" 1073741824 "Ti" 1099511627776 "k" 1000 "M" 1000000 "G" 1000000000 "T" 1000000000000 -}}
{{- $bytes := 0 -}}
{{- $num := regexFind "^[0-9]+" $q -}}
{{- $suffix := trimPrefix $num $q -}}
{{- if not $num }}{{- fail (printf "audit.sizeLimit %q is not a quantity" $q) }}{{- end }}
{{- if eq $suffix "" }}{{- $bytes = int64 $num }}
{{- else if hasKey $units $suffix }}{{- $bytes = mul (int64 $num) (get $units $suffix) }}
{{- else }}{{- fail (printf "audit.sizeLimit %q: unsupported unit %q" $q $suffix) }}{{- end }}
{{- $rot := .Values.audit.rotation -}}
{{- $need := add 1048576 (mul (add1 (int64 $rot.retainSegments)) (int64 $rot.maxSegmentBytes)) -}}
{{- if gt (mul $need 10) (mul $bytes 9) }}
{{- fail (printf "audit: (retainSegments + 1) x maxSegmentBytes + 1Mi = %d bytes does not fit in 90%% of sizeLimit %s; raise sizeLimit, lower audit.rotation, or set audit.existingClaim (UPGRADING-4.0 item 49)" $need $q) }}
{{- end }}
{{- end }}
