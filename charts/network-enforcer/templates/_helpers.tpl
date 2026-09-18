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
Create chart name and version as used by the chart label.
*/}}
{{- define "network-enforcer.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "network-enforcer.labels" -}}
helm.sh/chart: {{ include "network-enforcer.chart" . }}
{{ include "network-enforcer.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
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
Resolved provider endpoint (configured or default by provider).
Defaults:
- istio: 4317
- cilium: hubble-relay.kube-system.svc:80
- calico: goldmane.calico-system.svc:7443
*/}}
{{- define "network-enforcer.controller.providerEndpoint" -}}
{{- $provider := default "istio" .Values.controller.provider.name -}}
{{- $endpoint := .Values.controller.provider.endpoint -}}
{{- if not (empty $endpoint) -}}
{{- $endpoint -}}
{{- else if eq $provider "istio" -}}
4317
{{- else if eq $provider "cilium" -}}
hubble-relay.kube-system.svc:80
{{- else if eq $provider "calico" -}}
goldmane.calico-system.svc:7443
{{- else -}}
{{- fail (printf "unsupported controller.provider.name %q" $provider) -}}
{{- end -}}
{{- end -}}

{{/*
Validated Istio OTLP port.
Accepts configured int/string or provider default from helper.
*/}}
{{- define "network-enforcer.controller.istioPort" -}}
{{- $raw := include "network-enforcer.controller.providerEndpoint" . | trim -}}
{{- if not (regexMatch "^[0-9]{1,5}$" $raw) -}}
{{- fail (printf "controller.provider.endpoint must be a numeric port when controller.provider.name=istio (got %q)" $raw) -}}
{{- end -}}
{{- $port := atoi $raw -}}
{{- if or (lt $port 1) (gt $port 65535) -}}
{{- fail (printf "controller.provider.endpoint must be in range 1-65535 when controller.provider.name=istio (got %d)" $port) -}}
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
Directory where Goldmane mTLS material is mounted in the controller.
*/}}
{{- define "network-enforcer.goldmane.certDir" -}}
/etc/goldmane/certs
{{- end -}}

{{/*
Secret name of the Goldmane client certs mounted for the default Calico path.
*/}}
{{- define "network-enforcer.goldmane.secretName" -}}
net-enf-goldmane-client-certs
{{- end -}}

{{/*
Directory where generic provider TLS material is mounted (CSI or a local Secret).
*/}}
{{- define "network-enforcer.provider.tls.certDir" -}}
/etc/provider/certs
{{- end -}}

{{/*
Resolved provider TLS mode. Defaults to insecure.
TODO: default to issuer once the Istio and Cilium hops support TLS.
*/}}
{{- define "network-enforcer.provider.tls.mode" -}}
{{- $tls := default dict .Values.controller.provider.tls -}}
{{- default "insecure" $tls.mode -}}
{{- end -}}

{{/*
True when the Calico Goldmane Secret should be mounted in the pod.
TODO: drop this once Calico reads TLS material via existingSecret.
Until then, insecure Calico still mounts the release-namespace client Secret.
*/}}
{{- define "network-enforcer.provider.tls.mountGoldmaneSecret" -}}
{{- $mode := include "network-enforcer.provider.tls.mode" . | trim -}}
{{- $tls := default dict .Values.controller.provider.tls -}}
{{- $secret := default dict $tls.existingSecret -}}
{{- $remote := and $secret.name $secret.namespace -}}
{{- if and (eq (default "istio" .Values.controller.provider.name) "calico") (eq $mode "insecure") (not $remote) -}}
true
{{- end -}}
{{- end -}}

{{/*
True when provider TLS material is read from the API server (cross-namespace Secret).
*/}}
{{- define "network-enforcer.provider.tls.apiSecret" -}}
{{- $mode := include "network-enforcer.provider.tls.mode" . | trim -}}
{{- $tls := default dict .Values.controller.provider.tls -}}
{{- $secret := default dict $tls.existingSecret -}}
{{- if and (eq $mode "existingSecret") $secret.name $secret.namespace -}}
true
{{- end -}}
{{- end -}}

{{/*
Validate provider TLS values and fail at template time.
*/}}
{{- define "network-enforcer.provider.tls.validate" -}}
{{- $mode := include "network-enforcer.provider.tls.mode" . | trim -}}
{{- $tls := default dict .Values.controller.provider.tls -}}
{{- $issuer := default dict $tls.issuerRef -}}
{{- $secret := default dict $tls.existingSecret -}}
{{- if not (has $mode (list "issuer" "existingSecret" "insecure")) -}}
{{- fail (printf "controller.provider.tls.mode must be issuer, existingSecret, or insecure (got %q)" $mode) -}}
{{- end -}}
{{- if and (eq $mode "issuer") (not $issuer.name) -}}
{{- fail "controller.provider.tls.issuerRef.name is required when controller.provider.tls.mode=issuer" -}}
{{- end -}}
{{- if and (eq $mode "existingSecret") $secret.namespace (not $secret.name) -}}
{{- fail "controller.provider.tls.existingSecret.name is required when existingSecret.namespace is set" -}}
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
{{- $tls := default dict .Values.controller.provider.tls -}}
{{- $secret := default dict $tls.existingSecret }}
- --provider-tls-cert-secret={{ $secret.namespace }}/{{ $secret.name }}
{{- if $secret.caBundleConfigMap }}
- --provider-tls-ca-configmap={{ $secret.namespace }}/{{ $secret.caBundleConfigMap }}
{{- end }}
{{- else if eq $mode "existingSecret" }}
- --provider-tls-cert-dir={{ include "network-enforcer.provider.tls.certDir" . }}
{{- end -}}
{{- end -}}

{{/*
Volume mounts for provider TLS material.
*/}}
{{- define "network-enforcer.provider.tls.volumeMounts" -}}
{{- include "network-enforcer.provider.tls.validate" . -}}
{{- $mode := include "network-enforcer.provider.tls.mode" . | trim -}}
{{- if eq (include "network-enforcer.provider.tls.mountGoldmaneSecret" . | trim) "true" }}
- name: goldmane-certs
  mountPath: {{ include "network-enforcer.goldmane.certDir" . }}
  readOnly: true
{{- else if eq $mode "issuer" }}
- name: provider-tls
  mountPath: {{ include "network-enforcer.provider.tls.certDir" . }}
  readOnly: true
{{- else if and (eq $mode "existingSecret") (ne (include "network-enforcer.provider.tls.apiSecret" . | trim) "true") }}
{{- $tls := default dict .Values.controller.provider.tls -}}
{{- $secret := default dict $tls.existingSecret -}}
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
{{- $tls := default dict .Values.controller.provider.tls -}}
{{- $issuer := default dict $tls.issuerRef -}}
{{- $secret := default dict $tls.existingSecret -}}
{{- if eq (include "network-enforcer.provider.tls.mountGoldmaneSecret" . | trim) "true" }}
- name: goldmane-certs
  secret:
    secretName: {{ include "network-enforcer.goldmane.secretName" . }}
{{- else if eq $mode "issuer" }}
- name: provider-tls
  csi:
    driver: "csi.cert-manager.io"
    readOnly: true
    volumeAttributes:
      csi.cert-manager.io/issuer-name: {{ $issuer.name }}
      csi.cert-manager.io/issuer-kind: {{ default "Issuer" $issuer.kind }}
      {{- if $issuer.group }}
      csi.cert-manager.io/issuer-group: {{ $issuer.group }}
      {{- end }}
      csi.cert-manager.io/dns-names: {{ include "network-enforcer.fullname" . }}-controller-manager
{{- else if and (eq $mode "existingSecret") $secret.name (not $secret.namespace) }}
- name: provider-tls
  secret:
    secretName: {{ $secret.name }}
{{- end -}}
{{- end -}}

{{/*
Certificate directory for the shipped OTel collector's own (server-side) mTLS
keys, mounted via cert-manager CSI.
*/}}
{{- define "network-enforcer.otelCollector.certDir" -}}
/etc/otel-collector/certs
{{- end -}}

{{/*
CA certificate path used by the controller when sending OTLP logs to the
shipped in-cluster collector.
*/}}
{{- define "network-enforcer.otel.caCertDir" -}}
/tmp/otel-collector-certs
{{- end -}}
{{- define "network-enforcer.otel.caCertPath" -}}
{{ include "network-enforcer.otel.caCertDir" . }}/ca.crt
{{- end -}}


{{/*
Print the otel environment variable settings.
*/}}
{{- define "network-enforcer.otel.config.env" }}
{{- if eq .Values.telemetry.collectorStrategy "default" }}
- name: OTEL_EXPORTER_OTLP_ENDPOINT
  value: https://{{ include "network-enforcer.fullname" . }}-otel-collector.{{ .Release.Namespace }}.svc.cluster.local:4317
- name: OTEL_EXPORTER_OTLP_PROTOCOL
  value: grpc
- name: OTEL_EXPORTER_OTLP_CERTIFICATE
  value: {{ include "network-enforcer.otel.caCertPath" . }}
{{- else if eq .Values.telemetry.collectorStrategy "external" }}
- name: OTEL_EXPORTER_OTLP_ENDPOINT
  value: {{ .Values.telemetry.externalCollector.endpoint }}
- name: OTEL_EXPORTER_OTLP_PROTOCOL
  value: {{ .Values.telemetry.externalCollector.protocol }}
{{- if .Values.telemetry.externalCollector.otelCollectorCertificateSecret }}
- name: OTEL_EXPORTER_OTLP_CERTIFICATE
  value: {{ include "network-enforcer.otel.caCertPath" . }}
{{- else }}
- name: OTEL_EXPORTER_OTLP_INSECURE
  value: "true"
{{- end }}
{{- if .Values.telemetry.externalCollector.otelCollectorClientCertificateSecret }}
- name: OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE
  value: /tmp/otel-collector-client-certs/tls.crt
- name: OTEL_EXPORTER_OTLP_CLIENT_KEY
  value: /tmp/otel-collector-client-certs/tls.key
{{- end }}
{{- end }}
{{- end }}

{{/*
Print the otel volumeMounts settings.
The strategy gate mirrors network-enforcer.otel.config.volumes so mounts and
volumes are always emitted (or omitted) as a pair.
*/}}
{{- define "network-enforcer.otel.config.volumeMounts" }}
{{- if or (eq .Values.telemetry.collectorStrategy "default") (and (eq .Values.telemetry.collectorStrategy "external") .Values.telemetry.externalCollector.otelCollectorCertificateSecret) }}
- name: otel-collector-ca-cert
  mountPath: {{ include "network-enforcer.otel.caCertDir" . }}
  readOnly: true
{{- end }}
{{- if and (eq .Values.telemetry.collectorStrategy "external") .Values.telemetry.externalCollector.otelCollectorClientCertificateSecret }}
- name: otel-collector-client-cert
  mountPath: /tmp/otel-collector-client-certs
  readOnly: true
{{- end }}
{{- end }}

{{/*
Print the otel volumes settings.
*/}}
{{- define "network-enforcer.otel.config.volumes" }}
{{- if eq .Values.telemetry.collectorStrategy "default" }}
- name: otel-collector-ca-cert
  secret:
    secretName: {{ include "network-enforcer.caSecretName" . }}
    items:
    - key: ca.crt
      path: ca.crt
{{- end }}
{{- if and (eq .Values.telemetry.collectorStrategy "external") .Values.telemetry.externalCollector.otelCollectorCertificateSecret }}
- name: otel-collector-ca-cert
  secret:
    secretName: {{ .Values.telemetry.externalCollector.otelCollectorCertificateSecret }}
{{- end }}
{{- if and (eq .Values.telemetry.collectorStrategy "external") .Values.telemetry.externalCollector.otelCollectorClientCertificateSecret }}
- name: otel-collector-client-cert
  secret:
    secretName: {{ .Values.telemetry.externalCollector.otelCollectorClientCertificateSecret }}
{{- end }}
{{- end }}

{{/*
Certificate helpers for mTLS (CA issuer and secret share a name).
*/}}
{{- define "network-enforcer.caIssuerName" -}}
{{ include "network-enforcer.fullname" . }}-ca
{{- end -}}
{{- define "network-enforcer.caSecretName" -}}
{{ include "network-enforcer.fullname" . }}-ca
{{- end -}}
