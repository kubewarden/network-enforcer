{{/*
Expand the name of the chart.
*/}}
{{- define "network-enforcer.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "network-enforcer.fullname" -}}
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
Create the webhook Service name within the Kubernetes 63-character limit.
*/}}
{{- define "network-enforcer.webhookServiceName" -}}
{{- printf "%s-controller-webhook" (include "network-enforcer.fullname" . | trunc 44 | trimSuffix "-") }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "network-enforcer.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Namespace for all namespaced resources of the chart.
It is namespaceOverride, or the release namespace when namespaceOverride is empty.
This chart has no NATS subchart, so it has no nats.namespaceOverride check.
*/}}
{{- define "network-enforcer.namespace" -}}
{{- $override := .Values.namespaceOverride | default "" -}}
{{- $override | default .Release.Namespace -}}
{{- end -}}

{{/*
Registry prefix for the chart images, with a trailing "/".
global.imageRegistry wins over the workload imageRegistry.
This chart has no NATS subchart, so it has no NATS registry check.
*/}}
{{- define "system_default_registry" -}}
{{- $l := include "network-enforcer._levels" (dict "ctx" . "key" "imageRegistry") | fromYamlArray -}}
{{- with index $l 0 | default (index $l 2) -}}
{{- printf "%s/" . -}}
{{- end -}}
{{- end -}}

{{/*
Common labels
*/}}
{{- define "network-enforcer.labels" -}}
helm.sh/chart: {{ include "network-enforcer.chart" . }}
{{ include "network-enforcer.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/part-of: network-enforcer
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "network-enforcer.selectorLabels" -}}
app.kubernetes.io/name: {{ include "network-enforcer.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Name of the controller OTLP service used to reach the istio scraper.
*/}}
{{- define "network-enforcer.controller.istioService" -}}
{{ include "network-enforcer.fullname" . }}-istio-otlp
{{- end -}}

{{/*
Resolved provider name.
*/}}
{{- define "network-enforcer.provider.name" -}}
{{- default "istio" .Values.controller.provider.name -}}
{{- end -}}

{{/*
Active provider config object (controller.provider.<name>).
*/}}
{{- define "network-enforcer.provider.active" -}}
{{- $name := include "network-enforcer.provider.name" . -}}
{{- if not (has $name (list "istio" "cilium" "calico")) -}}
{{- fail (printf "unsupported controller.provider.name %q" $name) -}}
{{- end -}}
{{- $cfg := index .Values.controller.provider $name | default dict -}}
{{- if not $cfg -}}
{{- fail (printf "controller.provider.%s is required when controller.provider.name=%q" $name $name) -}}
{{- end -}}
{{- $cfg | toJson -}}
{{- end -}}

{{/*
TLS values for the active provider.
*/}}
{{- define "network-enforcer.provider.tls.values" -}}
{{- $cfg := include "network-enforcer.provider.active" . | fromJson -}}
{{- default dict $cfg.tls | toJson -}}
{{- end -}}

{{/*
Resolved provider endpoint from controller.provider.<name>.endpoint.
Cilium: when tls.mode=insecure and endpoint is still the TLS default (...:443),
rewrite the port to 80. This only adjusts the endpoint; plaintext also requires
clearing tls.serverName (the chart rejects a non-empty serverName when insecure).
*/}}
{{- define "network-enforcer.controller.providerEndpoint" -}}
{{- $name := include "network-enforcer.provider.name" . -}}
{{- $cfg := include "network-enforcer.provider.active" . | fromJson -}}
{{- $endpoint := $cfg.endpoint | default "" | toString -}}
{{- $mode := include "network-enforcer.provider.tls.mode" . | trim -}}
{{- if and (eq $name "cilium") (eq $mode "insecure") (or (empty $endpoint) (eq $endpoint "hubble-relay.kube-system.svc:443")) -}}
hubble-relay.kube-system.svc:80
{{- else if empty $endpoint -}}
{{- fail (printf "controller.provider.%s.endpoint is required" $name) -}}
{{- else -}}
{{- $endpoint -}}
{{- end -}}
{{- end -}}

{{/*
Validated Istio OTLP port.
Accepts configured int/string from controller.provider.istio.endpoint.
*/}}
{{- define "network-enforcer.controller.istioPort" -}}
{{- $raw := include "network-enforcer.controller.providerEndpoint" . | trim -}}
{{- if not (regexMatch "^[0-9]{1,5}$" $raw) -}}
{{- fail (printf "controller.provider.istio.endpoint must be a numeric port when controller.provider.name=istio (got %q)" $raw) -}}
{{- end -}}
{{- $port := atoi $raw -}}
{{- if or (lt $port 1) (gt $port 65535) -}}
{{- fail (printf "controller.provider.istio.endpoint must be in range 1-65535 when controller.provider.name=istio (got %d)" $port) -}}
{{- end -}}
{{- $port -}}
{{- end -}}

{{/*
Port the controller health/readiness probe endpoint binds to.
Internal wiring: kept in a single place so the --health-probe-bind-address flag
and the liveness/readiness probes cannot drift. Not user configurable.
*/}}
{{- define "network-enforcer.controller.probePort" -}}
8081
{{- end -}}

{{/*
Directory where generic provider TLS material is mounted (CSI or a local Secret).
*/}}
{{- define "network-enforcer.provider.tls.certDir" -}}
/etc/provider/certs
{{- end -}}

{{/*
TLS mode for the active provider.
*/}}
{{- define "network-enforcer.provider.tls.mode" -}}
{{- $tls := include "network-enforcer.provider.tls.values" . | fromJson -}}
{{- $mode := default "" $tls.mode -}}
{{- if not $mode -}}
{{- fail (printf "controller.provider.%s.tls.mode is required" (include "network-enforcer.provider.name" .)) -}}
{{- end -}}
{{- $mode -}}
{{- end -}}

{{/*
cert-manager Issuer name used when mode=issuer.
Falls back to the chart CA Issuer when issuerRef.name is empty.
*/}}
{{- define "network-enforcer.provider.tls.issuerName" -}}
{{- $tls := include "network-enforcer.provider.tls.values" . | fromJson -}}
{{- $issuer := default dict $tls.issuerRef -}}
{{- if $issuer.name -}}
{{- $issuer.name -}}
{{- else -}}
{{- include "network-enforcer.caIssuerName" . -}}
{{- end -}}
{{- end -}}

{{/*
DNS SANs for the provider TLS certificate issued via CSI.
Istio is a server hop, so the names must match the istio-otlp Service.
Cilium's client certificate only has to sit in Cilium's own name space.
*/}}
{{- define "network-enforcer.provider.tls.dnsNames" -}}
{{- $provider := include "network-enforcer.provider.name" . -}}
{{- if eq $provider "istio" -}}
{{- $svc := include "network-enforcer.controller.istioService" . -}}
{{- $ns := include "network-enforcer.namespace" . -}}
{{- printf "%s,%s.%s,%s.%s.svc,%s.%s.svc.%s" $svc $svc $ns $svc $ns $svc $ns .Values.kubernetesClusterDomain -}}
{{- else if eq $provider "cilium" -}}
network-enforcer.hubble-relay.cilium.io
{{- else -}}
{{ include "network-enforcer.fullname" . }}-controller-manager
{{- end -}}
{{- end -}}

{{/*
Existing Secret settings for the active provider.
*/}}
{{- define "network-enforcer.provider.tls.existingSecret" -}}
{{- $tls := include "network-enforcer.provider.tls.values" . | fromJson -}}
{{- $secret := default dict $tls.existingSecret -}}
{{- dict "name" (default "" $secret.name) "namespace" (default "" $secret.namespace) "caBundleConfigMap" (default "" $secret.caBundleConfigMap) "caBundleKey" (default "ca.crt" $secret.caBundleKey) | toJson -}}
{{- end -}}

{{/*
Resolved TLS server name; empty defers to the endpoint host.
*/}}
{{- define "network-enforcer.provider.tls.serverName" -}}
{{- $tls := include "network-enforcer.provider.tls.values" . | fromJson -}}
{{- $mode := include "network-enforcer.provider.tls.mode" . | trim -}}
{{- if eq $mode "insecure" -}}
{{- else if $tls.serverName -}}
{{- $tls.serverName -}}
{{- end -}}
{{- end -}}

{{/*
True when provider TLS material is read from the API server (cross-namespace Secret).
*/}}
{{- define "network-enforcer.provider.tls.apiSecret" -}}
{{- $mode := include "network-enforcer.provider.tls.mode" . | trim -}}
{{- $secret := include "network-enforcer.provider.tls.existingSecret" . | fromJson -}}
{{- if and (eq $mode "existingSecret") $secret.name $secret.namespace -}}
true
{{- end -}}
{{- end -}}

{{/*
Validate provider TLS values and fail at template time.
*/}}
{{- define "network-enforcer.provider.tls.validate" -}}
{{- $path := printf "controller.provider.%s.tls" (include "network-enforcer.provider.name" .) -}}
{{- $mode := include "network-enforcer.provider.tls.mode" . | trim -}}
{{- $tls := include "network-enforcer.provider.tls.values" . | fromJson -}}
{{- $secret := include "network-enforcer.provider.tls.existingSecret" . | fromJson -}}
{{- $provider := include "network-enforcer.provider.name" . -}}
{{- if and (eq $provider "calico") (eq $mode "insecure") -}}
{{- fail (printf "%s.mode=insecure is not supported when controller.provider.name=calico; Goldmane requires mTLS (use existingSecret or issuer)" $path) -}}
{{- end -}}
{{- if not (has $mode (list "issuer" "existingSecret" "insecure")) -}}
{{- fail (printf "%s.mode must be issuer, existingSecret, or insecure (got %q)" $path $mode) -}}
{{- end -}}
{{- if and (eq $mode "issuer") (not (include "network-enforcer.provider.tls.issuerName" . | trim)) -}}
{{- fail (printf "%s.issuerRef.name is required when %s.mode=issuer" $path $path) -}}
{{- end -}}
{{- if and (eq $mode "existingSecret") (not $secret.name) -}}
{{- fail (printf "%s.existingSecret.name is required when %s.mode=existingSecret" $path $path) -}}
{{- end -}}
{{/*
Istio is a TLS server, so it needs tls.crt/tls.key mounted: only a same-namespace Secret or issuer CSI works.
*/}}
{{- if and (eq $provider "istio") (eq (include "network-enforcer.provider.tls.apiSecret" . | trim) "true") -}}
{{- fail (printf "%s.existingSecret.namespace cannot be set when controller.provider.name=istio; the Istio scraper is a TLS server and needs tls.crt/tls.key mounted in the pod" $path) -}}
{{- end -}}
{{- if and (eq $mode "insecure") $tls.serverName -}}
{{- fail (printf "%s.serverName is not accepted when %s.mode=insecure" $path $path) -}}
{{- end -}}
{{- end -}}

{{/*
Controller flags for the provider TLS hop.
*/}}
{{- define "network-enforcer.provider.tls.args" -}}
{{- include "network-enforcer.provider.tls.validate" . -}}
{{- $mode := include "network-enforcer.provider.tls.mode" . | trim }}
- --provider-tls-mode={{ $mode }}
{{- if eq $mode "issuer" }}
- --provider-tls-cert-dir={{ include "network-enforcer.provider.tls.certDir" . }}
{{- else if and (eq $mode "existingSecret") (eq (include "network-enforcer.provider.tls.apiSecret" . | trim) "true") }}
{{- $secret := include "network-enforcer.provider.tls.existingSecret" . | fromJson }}
- --provider-tls-cert-secret={{ $secret.namespace }}/{{ $secret.name }}
{{- if $secret.caBundleConfigMap }}
- --provider-tls-ca-configmap={{ $secret.namespace }}/{{ $secret.caBundleConfigMap }}
- --provider-tls-ca-bundle-key={{ default "ca.crt" $secret.caBundleKey }}
{{- end }}
{{- else if eq $mode "existingSecret" }}
- --provider-tls-cert-dir={{ include "network-enforcer.provider.tls.certDir" . }}
{{- end }}
{{- $serverName := include "network-enforcer.provider.tls.serverName" . | trim }}
{{- if $serverName }}
- --provider-tls-server-name={{ $serverName }}
{{- end }}
{{- end -}}

{{/*
Volume mounts for provider TLS material.
*/}}
{{- define "network-enforcer.provider.tls.volumeMounts" -}}
{{- include "network-enforcer.provider.tls.validate" . -}}
{{- $mode := include "network-enforcer.provider.tls.mode" . | trim -}}
{{- if eq $mode "issuer" }}
- name: provider-tls
  mountPath: {{ include "network-enforcer.provider.tls.certDir" . }}
  readOnly: true
{{- else if and (eq $mode "existingSecret") (ne (include "network-enforcer.provider.tls.apiSecret" . | trim) "true") }}
{{- $secret := include "network-enforcer.provider.tls.existingSecret" . | fromJson -}}
{{- if and $secret.name (not $secret.namespace) }}
- name: provider-tls
  mountPath: {{ include "network-enforcer.provider.tls.certDir" . }}
  readOnly: true
{{- end }}
{{- end -}}
{{- end -}}

{{/*
Volumes for provider TLS material.
*/}}
{{- define "network-enforcer.provider.tls.volumes" -}}
{{- include "network-enforcer.provider.tls.validate" . -}}
{{- $mode := include "network-enforcer.provider.tls.mode" . | trim -}}
{{- $tls := include "network-enforcer.provider.tls.values" . | fromJson -}}
{{- $issuer := default dict $tls.issuerRef -}}
{{- $secret := include "network-enforcer.provider.tls.existingSecret" . | fromJson -}}
{{- if eq $mode "issuer" }}
- name: provider-tls
  csi:
    driver: "csi.cert-manager.io"
    readOnly: true
    volumeAttributes:
      csi.cert-manager.io/issuer-name: {{ include "network-enforcer.provider.tls.issuerName" . }}
      csi.cert-manager.io/issuer-kind: {{ default "Issuer" $issuer.kind }}
      {{- if $issuer.group }}
      csi.cert-manager.io/issuer-group: {{ $issuer.group }}
      {{- end }}
      csi.cert-manager.io/dns-names: {{ include "network-enforcer.provider.tls.dnsNames" . }}
{{- else if and (eq $mode "existingSecret") $secret.name (not $secret.namespace) }}
- name: provider-tls
  secret:
    secretName: {{ $secret.name }}
{{- end -}}
{{- end -}}

{{/*
Volume mounts for the Istio fluent-bit client certificate.
*/}}
{{- define "network-enforcer.istio.fluentBit.tls.volumeMounts" -}}
{{- include "network-enforcer.provider.tls.validate" . -}}
{{- $mode := include "network-enforcer.provider.tls.mode" . | trim -}}
{{- if or (eq $mode "issuer") (and (eq $mode "existingSecret") (ne (include "network-enforcer.provider.tls.apiSecret" . | trim) "true")) }}
- name: provider-tls
  mountPath: {{ include "network-enforcer.provider.tls.certDir" . }}
  readOnly: true
{{- end -}}
{{- end -}}

{{/*
Volumes for the Istio fluent-bit client certificate.
Issuer mode uses cert-manager CSI with a per-Pod client cert. A same-namespace
existingSecret is mounted as-is.
*/}}
{{- define "network-enforcer.istio.fluentBit.tls.volumes" -}}
{{- include "network-enforcer.provider.tls.validate" . -}}
{{- $mode := include "network-enforcer.provider.tls.mode" . | trim -}}
{{- $tls := include "network-enforcer.provider.tls.values" . | fromJson -}}
{{- $issuer := default dict $tls.issuerRef -}}
{{- $secret := default dict $tls.existingSecret -}}
{{- if eq $mode "issuer" }}
- name: provider-tls
  csi:
    driver: "csi.cert-manager.io"
    readOnly: true
    volumeAttributes:
      csi.cert-manager.io/issuer-name: {{ include "network-enforcer.provider.tls.issuerName" . }}
      csi.cert-manager.io/issuer-kind: {{ default "Issuer" $issuer.kind }}
      {{- if $issuer.group }}
      csi.cert-manager.io/issuer-group: {{ $issuer.group }}
      {{- end }}
      csi.cert-manager.io/dns-names: {{ include "network-enforcer.fullname" . }}-istio-fluent-bit
{{- else if and (eq $mode "existingSecret") $secret.name (not $secret.namespace) }}
- name: provider-tls
  secret:
    secretName: {{ $secret.name }}
{{- end -}}
{{- end -}}

{{/*
Certificate helpers for mTLS (CA issuer and secret share a name).
*/}}
{{- define "network-enforcer.caIssuerName" -}}
{{ include "network-enforcer.fullname" . }}-ca
{{- end -}}
{{- define "network-enforcer.caSecretName" -}}
{{ include "network-enforcer.fullname" . }}-ca
{{- end -}}

{{/*
Values of the workloads

The workload templates read their values through the public helpers below.
Each public helper takes a context dict:
  root:      the root context ($)
  workload:  the name of the workload block in .Values: "controller" or "istioFluentBit"
  component: the value of the app.kubernetes.io/component label, for example "controller"
A context dict can also have:
  fixedWorkloadLabels: a map of extra fixed labels for the workload resource
                       (not the pod), for example the control-plane label.

A template builds the context dict once:
  {{- $ctx := dict "root" $ "workload" "controller" "component" "controller" }}

Each public helper reads one key with one private helper. The private helper sets the rule:
  network-enforcer._scalar: the workload value, else the common value, else the global value.
  network-enforcer._list:   the same rule as network-enforcer._scalar, for a list.
  network-enforcer._map:    the global, common, and workload maps merged. The workload wins on a duplicate key.
  network-enforcer._concat: the global, common, and workload lists, in this order.
An empty value ("", [] or {}) counts as unset.
system_default_registry (above) uses its own order and does not read common.

The private helpers take dict "ctx" <context dict> "key" <key>.
A key with a dot, for example "serviceAccount.annotations", reads a nested map.
Templates do not call the private helpers.
*/}}

{{/*
network-enforcer._levels renders a YAML list with three items:
the value of the key in global, in common, and in the workload block.
The other private helpers decode this list, so they work on copies of .Values.
*/}}
{{- define "network-enforcer._levels" -}}
{{- $values := .ctx.root.Values -}}
{{- $blocks := list ($values.global | default dict) ($values.common | default dict) (index $values .ctx.workload | default dict) -}}
{{- $out := list -}}
{{- range $block := $blocks -}}
{{- $value := $block -}}
{{- range $part := splitList "." $.key -}}
{{- $value = index ($value | default dict) $part -}}
{{- end -}}
{{- $out = append $out $value -}}
{{- end -}}
{{- toYaml $out -}}
{{- end -}}

{{- define "network-enforcer._scalar" -}}
{{- $l := include "network-enforcer._levels" . | fromYamlArray -}}
{{- index $l 2 | default (index $l 1) | default (index $l 0) | default "" -}}
{{- end -}}

{{- define "network-enforcer._list" -}}
{{- $l := include "network-enforcer._levels" . | fromYamlArray -}}
{{- toYaml (index $l 2 | default (index $l 1) | default (index $l 0) | default list) -}}
{{- end -}}

{{- define "network-enforcer._map" -}}
{{- $l := include "network-enforcer._levels" . | fromYamlArray -}}
{{- toYaml (mergeOverwrite (dict) (index $l 0 | default dict) (index $l 1 | default dict) (index $l 2 | default dict)) -}}
{{- end -}}

{{- define "network-enforcer._concat" -}}
{{- $l := include "network-enforcer._levels" . | fromYamlArray -}}
{{- toYaml (concat (index $l 0 | default list) (index $l 1 | default list) (index $l 2 | default list)) -}}
{{- end -}}

{{/*
network-enforcer._field renders "<name>:" and the value as YAML.
It renders nothing when the value is empty.
It takes dict "name" <field name> "value" <value>.
*/}}
{{- define "network-enforcer._field" -}}
{{- with .value -}}
{{ $.name }}:
  {{- toYaml . | nindent 2 }}
{{- end -}}
{{- end -}}

{{/*
network-enforcer._labels renders "labels:" with the merged map of the key
and the fixed chart labels. The fixed chart labels win on a duplicate key.
It takes dict "ctx" <context dict> "key" <key> and an optional "fixed" map
of extra fixed labels.
*/}}
{{- define "network-enforcer._labels" -}}
{{- $labels := include "network-enforcer._map" . | fromYaml -}}
{{- $fixed := include "network-enforcer.labels" .ctx.root | fromYaml -}}
{{- $_ := set $fixed "app.kubernetes.io/component" .ctx.component -}}
{{- $fixed = mergeOverwrite $fixed (.fixed | default dict) -}}
labels:
  {{- toYaml (mergeOverwrite $labels $fixed) | nindent 2 }}
{{- end -}}

{{/* Public helpers that render a bare value. */}}

{{- define "network-enforcer.imagePullPolicy" -}}
{{- include "network-enforcer._scalar" (dict "ctx" . "key" "imagePullPolicy") -}}
{{- end -}}

{{- define "network-enforcer.logLevel" -}}
{{- include "network-enforcer._scalar" (dict "ctx" . "key" "logLevel") -}}
{{- end -}}

{{/* Public helpers that render a whole field, or nothing when the value is empty. */}}

{{/*
network-enforcer.priorityClassName renders "priorityClassName:".
The name is the workload value, else common, else global.
When none is set, the controller and the Istio fluent-bit DaemonSet use priorityClass.name.
*/}}
{{- define "network-enforcer.priorityClassName" -}}
{{- $name := include "network-enforcer._scalar" (dict "ctx" . "key" "priorityClassName") -}}
{{- if and (not $name) (has .workload (list "controller" "istioFluentBit")) -}}
{{- $name = .root.Values.priorityClass.name | default "" -}}
{{- end -}}
{{- with $name -}}
priorityClassName: {{ . | quote }}
{{- end -}}
{{- end -}}

{{- define "network-enforcer.tolerations" -}}
{{- include "network-enforcer._field" (dict "name" "tolerations" "value" (include "network-enforcer._list" (dict "ctx" . "key" "tolerations") | fromYamlArray)) -}}
{{- end -}}

{{- define "network-enforcer.topologySpreadConstraints" -}}
{{- include "network-enforcer._field" (dict "name" "topologySpreadConstraints" "value" (include "network-enforcer._list" (dict "ctx" . "key" "topologySpreadConstraints") | fromYamlArray)) -}}
{{- end -}}

{{- define "network-enforcer.extraEnvFrom" -}}
{{- include "network-enforcer._field" (dict "name" "envFrom" "value" (include "network-enforcer._list" (dict "ctx" . "key" "extraEnvFrom") | fromYamlArray)) -}}
{{- end -}}

{{- define "network-enforcer.nodeSelector" -}}
{{- include "network-enforcer._field" (dict "name" "nodeSelector" "value" (include "network-enforcer._map" (dict "ctx" . "key" "nodeSelector") | fromYaml)) -}}
{{- end -}}

{{- define "network-enforcer.affinity" -}}
{{- include "network-enforcer._field" (dict "name" "affinity" "value" (include "network-enforcer._map" (dict "ctx" . "key" "affinity") | fromYaml)) -}}
{{- end -}}

{{- define "network-enforcer.workloadAnnotations" -}}
{{- include "network-enforcer._field" (dict "name" "annotations" "value" (include "network-enforcer._map" (dict "ctx" . "key" "annotations") | fromYaml)) -}}
{{- end -}}

{{/*
network-enforcer.podAnnotations renders "annotations:" for the pod template.
It takes the context dict and an optional "fixedPodAnnotations" map in it.
The fixed annotations win on a duplicate key.
*/}}
{{- define "network-enforcer.podAnnotations" -}}
{{- $annotations := include "network-enforcer._map" (dict "ctx" . "key" "podAnnotations") | fromYaml -}}
{{- $annotations = mergeOverwrite $annotations (.fixedPodAnnotations | default dict) -}}
{{- include "network-enforcer._field" (dict "name" "annotations" "value" $annotations) -}}
{{- end -}}

{{- define "network-enforcer.serviceAccountAnnotations" -}}
{{- include "network-enforcer._field" (dict "name" "annotations" "value" (include "network-enforcer._map" (dict "ctx" . "key" "serviceAccount.annotations") | fromYaml)) -}}
{{- end -}}

{{- define "network-enforcer.workloadLabels" -}}
{{- include "network-enforcer._labels" (dict "ctx" . "key" "labels" "fixed" .fixedWorkloadLabels) -}}
{{- end -}}

{{- define "network-enforcer.podLabels" -}}
{{- include "network-enforcer._labels" (dict "ctx" . "key" "podLabels") -}}
{{- end -}}

{{/*
network-enforcer.imagePullSecrets renders "imagePullSecrets:" with the global,
common, and workload lists, in this order.
Each item is a Secret name or a map with a name key. The helper renders a
name as a map. It skips an item with an empty or missing name.
It keeps an item of any other type, and Kubernetes rejects it.
*/}}
{{- define "network-enforcer.imagePullSecrets" -}}
{{- $secrets := list -}}
{{- range include "network-enforcer._concat" (dict "ctx" . "key" "imagePullSecrets") | fromYamlArray -}}
{{- if kindIs "string" . -}}
{{- if . -}}
{{- $secrets = append $secrets (dict "name" .) -}}
{{- end -}}
{{- else if kindIs "map" . -}}
{{- if .name -}}
{{- $secrets = append $secrets . -}}
{{- end -}}
{{- else -}}
{{- $secrets = append $secrets . -}}
{{- end -}}
{{- end -}}
{{- include "network-enforcer._field" (dict "name" "imagePullSecrets" "value" $secrets) -}}
{{- end -}}

{{/* Public helpers that render list entries, or nothing when the list is empty. */}}

{{- define "network-enforcer.extraEnv" -}}
{{- with include "network-enforcer._concat" (dict "ctx" . "key" "extraEnv") | fromYamlArray -}}
{{- toYaml . -}}
{{- end -}}
{{- end -}}

{{- define "network-enforcer.extraVolumes" -}}
{{- with include "network-enforcer._concat" (dict "ctx" . "key" "extraVolumes") | fromYamlArray -}}
{{- toYaml . -}}
{{- end -}}
{{- end -}}

{{- define "network-enforcer.extraVolumeMounts" -}}
{{- with include "network-enforcer._concat" (dict "ctx" . "key" "extraVolumeMounts") | fromYamlArray -}}
{{- toYaml . -}}
{{- end -}}
{{- end -}}
