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
{{- if eq .Values.auth.mode "oidc" -}}
{{- $reasons = append $reasons "auth.mode oidc runs the key server, which keeps issued tokens and revocations in one process's InMemoryTokenStore; set replicaCount: 1." -}}
{{- end -}}
{{- if .Values.persistence.enabled -}}
{{- $reasons = append $reasons "persistence.enabled: the task and control-plane stores on the claim hold an exclusive lease, and a ReadWriteOnce claim attaches to one node; set replicaCount: 1." -}}
{{- end -}}
{{- if and .Values.audit.existingClaim (ne .Values.auth.mode "mesh") -}}
{{- $reasons = append $reasons "audit.existingClaim: one gateway process writes the audit log on that volume (a second is refused at startup); set replicaCount: 1, or give each replica its own volume." -}}
{{- end -}}
{{- join " " $reasons -}}
{{- end -}}

{{/* The server.cleartext_http value the gateway config renders, or "" when
     none is rendered. Every mode but mesh accepts a credential over the pod's
     plain-HTTP bind (a bearer, an API key, or a key-server token), and the
     gateway refuses to serve that without this answer (C3). */}}
{{- define "mcp-gateway.cleartextHttp" -}}
{{- if ne .Values.auth.mode "mesh" -}}
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

{{/* CHART.2: the credential references each auth mode renders, as a JSON
     list of {env, key}: the ConfigMap writes env:<env> from it and the
     Deployment injects <env> from auth.existingSecret key <key>. The ConfigMap references exactly these names (config and env
     are both keyed on the mode here, so the two templates cannot drift):
       credential  MCP_GATEWAY_TOKEN          <- auth.secretKey
       api_keys    GATEWAY_API_KEY_<i>        <- auth.apiKeys[i].secretKey
       oidc        GATEWAY_KS_ADMIN_TOKEN     <- auth.oidc.adminTokenSecretKey, when set
       mesh        nothing
     Only credential gets the master bearer. */}}
{{- define "mcp-gateway.authRefs" -}}
{{- $mode := .Values.auth.mode -}}
{{- $refs := list -}}
{{- if eq $mode "credential" -}}
{{- $refs = append $refs (dict "env" "MCP_GATEWAY_TOKEN" "key" .Values.auth.secretKey) -}}
{{- else if eq $mode "api_keys" -}}
{{- range $i, $k := .Values.auth.apiKeys -}}
{{- $refs = append $refs (dict "env" (printf "GATEWAY_API_KEY_%d" $i) "key" $k.secretKey) -}}
{{- end -}}
{{- else if and (eq $mode "oidc") (dig "adminTokenSecretKey" "" (.Values.auth.oidc | default dict)) -}}
{{- $refs = append $refs (dict "env" "GATEWAY_KS_ADMIN_TOKEN" "key" .Values.auth.oidc.adminTokenSecretKey) -}}
{{- end -}}
{{- toJson $refs -}}
{{- end -}}

{{/* The pod env for mcp-gateway.authRefs, from auth.existingSecret. */}}
{{- define "mcp-gateway.authSecretEnv" -}}
{{- $refs := include "mcp-gateway.authRefs" . | fromJsonArray -}}
{{- if and $refs (not .Values.auth.existingSecret) -}}
{{- fail (printf "auth.existingSecret is required in %s mode: the rendered config references env:%s, and a pod without it fails validation at startup." .Values.auth.mode (index $refs 0).env) -}}
{{- end -}}
{{- if eq .Values.auth.mode "credential" }}
# The config references env:MCP_GATEWAY_TOKEN. A missing value fails
# validation at startup rather than serving without one, so an
# install that forgets the Secret stops instead of opening.
{{- end }}
{{- range $refs }}
- name: {{ .env }}
  valueFrom:
    secretKeyRef:
      name: {{ $.Values.auth.existingSecret | quote }}
      key: {{ .key | quote }}
{{- end -}}
{{- end -}}

{{/* CHART.2: MCP_GATEWAY_* variables override config (`__` nests, so
     MCP_GATEWAY_AUTH__ENABLED=false reaches auth.enabled). extraEnv may not
     set one, in any case, nor a chart-owned name; every envFrom entry needs a
     prefix that neither starts MCP_GATEWAY_ nor is a leading part of it, or a
     Secret key could complete the name (prefix MCP_ + key GATEWAY_AUTH__...). */}}
{{- define "mcp-gateway.envGuards" -}}
{{- $reserved := "MCP_GATEWAY_" -}}
{{- range .Values.extraEnv -}}
{{- $n := upper (toString .name) -}}
{{- if or (hasPrefix $reserved $n) (has $n (list "HOME" "GATEWAY_KS_ADMIN_TOKEN")) (hasPrefix "GATEWAY_API_KEY_" $n) -}}
{{- fail (printf "extraEnv name %q is reserved: MCP_GATEWAY_* variables override gateway config, and HOME, GATEWAY_API_KEY_* and GATEWAY_KS_ADMIN_TOKEN belong to the chart." .name) -}}
{{- end -}}
{{- end -}}
{{- range .Values.envFrom -}}
{{- $p := upper (toString (.prefix | default "")) -}}
{{- if not $p -}}
{{- fail "envFrom entries need a non-empty prefix: without one, a Secret key named MCP_GATEWAY_... would override gateway config." -}}
{{- end -}}
{{- $unsafe := false -}}
{{- range $r := list "MCP_GATEWAY_" "GATEWAY_API_KEY_" -}}
{{- if or (hasPrefix $r $p) (hasPrefix $p $r) -}}{{- $unsafe = true -}}{{- end -}}
{{- end -}}
{{- range $r := list "HOME" "GATEWAY_KS_ADMIN_TOKEN" -}}
{{- if hasPrefix $p $r -}}{{- $unsafe = true -}}{{- end -}}
{{- end -}}
{{- if $unsafe -}}
{{- fail (printf "envFrom prefix %q is unsafe: a Secret key could complete it to a reserved name (MCP_GATEWAY_*, GATEWAY_API_KEY_*, HOME, GATEWAY_KS_ADMIN_TOKEN)." .prefix) -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/* The chart-created state claim: 57 characters of fullname plus "-state",
     within the 63-character name limit. */}}
{{- define "mcp-gateway.stateClaim" -}}
{{- .Values.persistence.existingClaim | default (printf "%s-state" (include "mcp-gateway.fullname" . | trunc 57 | trimSuffix "-")) -}}
{{- end -}}
