[![Kubewarden Core Repository](https://github.com/kubewarden/community/blob/main/badges/kubewarden-core.svg)](https://github.com/kubewarden/community/blob/main/REPOSITORIES.md#core-scope)
[![Sandbox](https://img.shields.io/badge/status-sandbox-red?style=for-the-badge)](https://github.com/kubewarden/community/blob/main/REPOSITORIES.md#sandbox)
[![Artifact HUB](https://img.shields.io/badge/ArtifactHub-Helm_Charts-blue?style=flat&logo=artifacthub&link=https%3A%2F%2Fartifacthub.io%2Fpackages%2Fsearch%3Frepo%3Dkubewarden%26kind%3D0%26verified_publisher%3Dtrue%26official%3Dtrue%26cncf%3Dtrue%26sort%3Drelevance%26page%3D1)](https://artifacthub.io/packages/search?repo=kubewarden&kind=0&verified_publisher=true&official=true&cncf=true&sort=relevance&page=1)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/kubewarden/network-enforcer/badge)](https://scorecard.dev/viewer/?uri=github.com/kubewarden/network-enforcer)
[![CLOMonitor](https://img.shields.io/endpoint?url=https://clomonitor.io/api/projects/cncf/kubewarden/badge)](https://clomonitor.io/projects/cncf/kubewarden)

# Kubewarden Network Enforcer

> [!WARNING]
> This project is experimental and under active development. It is not yet
> a production-ready solution.

Kubewarden Network Enforcer is a Kubernetes security tool that helps teams
move from permissive networking to policy-driven cluster security.

It observes real network flows from running workloads, correlates traffic
patterns, and produces `WorkloadNetworkPolicyProposal` resources that describe
suggested ingress and egress rules. Teams review and approve these proposals
before they are enforced, so they keep control while reducing trial-and-error.

It operates in three phases:

- **Learn** — observe network flows and generate a `WorkloadNetworkPolicyProposal`
  per workload.
- **Monitor** — report flows that violate an approved `WorkloadNetworkPolicy`
  without blocking them.
- **Protect** — enforce the approved policy and block flows that violate it.

The project is built around a Kubernetes controller that manages the proposal
and policy lifecycle. The controller reads flow telemetry from the configured
data-plane provider: Istio ambient, Calico Goldmane, or Cilium Hubble Relay.
For Istio, the chart deploys a per-node agent that reads ztunnel logs.

The design documents are in the
[RFCs](https://github.com/kubewarden/network-enforcer/tree/main/docs/rfc).

## Documentation

The full documentation is available at
[docs.kubewarden.io/network-enforcer](https://docs.kubewarden.io/network-enforcer/latest/en/introduction.html).

- [Quick Start](https://docs.kubewarden.io/network-enforcer/latest/en/installation/quickstart.html)
  — deploy Network Enforcer and walk through the learn/monitor/protect workflow.
- [Compatibility](https://docs.kubewarden.io/network-enforcer/latest/en/compatibility.html)
  — provider and platform requirements.
- [Phases: learn, monitor, protect](https://docs.kubewarden.io/network-enforcer/latest/en/phases.html)
  — understand the learn, monitor and protect phases in detail.

## Installation

Network Enforcer is deployed with a Helm chart. The chart is published at
https://charts.kubewarden.io.

To check whether a published chart includes the Istio agent, look for
`controller.provider.istio.agent` in `helm show values kubewarden/network-enforcer`.
The [0.5 quick start](https://docs.kubewarden.io/network-enforcer/0.5/en/quickstart.html)
uses the development chart and matching images.

The chart needs Kubernetes 1.31 or later. The cluster must run one of the
supported data-plane providers: Istio ambient, Calico with Goldmane, or Cilium
with Hubble Relay. See
[Compatibility](https://docs.kubewarden.io/network-enforcer/latest/en/compatibility.html)
for the provider requirements.

The chart needs [cert-manager](https://cert-manager.io/) and the
[cert-manager-csi-driver](https://cert-manager.io/docs/usage/csi-driver/)
in the cluster. The
[Quick Start](https://docs.kubewarden.io/network-enforcer/latest/en/installation/quickstart.html)
shows how to install them.

The chart does not deploy an OpenTelemetry collector. The controller exports
violation events to a collector that you deploy. To turn on the export, set
`global.otel.endpoint`.

```sh
helm repo add kubewarden https://charts.kubewarden.io
helm repo update
helm install network-enforcer kubewarden/network-enforcer \
  --namespace network-enforcer \
  --create-namespace \
  --set controller.provider.name=istio \
  --wait
```

Set `controller.provider.name` to `istio`, `cilium`, or `calico` to match the
data-plane provider running in your cluster.

After installation, ensure all pods are running:

```sh
kubectl get pods -n network-enforcer
```

## Configuration

The top-level keys of
[`values.yaml`](https://github.com/kubewarden/network-enforcer/blob/main/charts/network-enforcer/values.yaml):

| Key                       | Description                                                                                                 |
| ------------------------- | ----------------------------------------------------------------------------------------------------------- |
| `namespaceOverride`       | The namespace of the chart resources. If it is empty, the chart uses the release namespace.                 |
| `global`                  | The values for all workloads: registry, pull secrets, log level, labels, scheduling, extra env, `otel`.     |
| `otel`                    | The telemetry export of this chart. A key that is set here wins over the workload `otel` and `global.otel`. |
| `controller`              | The controller Deployment: image, replicas, resources, security context, PodDisruptionBudget.               |
| `controller.provider`     | The data-plane provider (`istio`, `cilium`, `calico`), and per-provider endpoint/TLS settings where applicable. |
| `controller.provider.istio.agent` | Istio ztunnel log reader DaemonSet settings, enabled by default only for Istio. The controller uses authenticated mTLS by default even when local deployment is disabled. |
| `kubernetesClusterDomain` | The DNS domain of the cluster.                                                                              |
| `learning`                | The `namespaceSelector` that limits the namespaces where learning writes proposals. Set it to `null` to disable learning. |
| `priorityClass`           | The PriorityClass shared by the controller and agent pods. A `priorityClassName` overrides it.              |
| `nameOverride`            | Replaces the chart name in the generated resource names.                                                    |
| `fullnameOverride`        | Replaces the whole `<release>-<chart>` prefix in the generated resource names.                              |

### Provider endpoint and TLS

`controller.provider.name` selects which provider is active. Provider endpoint
and TLS settings live under the selected provider's tree where applicable.
Istio uses the nested `controller.provider.istio.agent.grpcPort` for the agent
pull port and chart-managed CSI mTLS.

| Provider | Default endpoint or port | Default TLS mode | Default material |
| -------- | ----------------------- | ---------------- | ---------------- |
| `istio` | agent pull port `50052` (`controller.provider.istio.agent.grpcPort`) | chart-managed mTLS | shared chart CA and per-agent CSI certificate |
| `cilium` | `hubble-relay.kube-system.svc:443` | `existingSecret` | `kube-system/hubble-relay-client-certs`, server name `ui.hubble-relay.cilium.io` |
| `calico` | `goldmane.calico-system.svc:7443` | `existingSecret` | `calico-system/goldmane-key-pair` + `goldmane-ca-bundle` (CA key `tigera-ca-bundle.crt`) |

Calico does not support `insecure`: Goldmane requires mTLS. Cilium `insecure` is
plaintext to Relay port 80: set `tls.mode=insecure` and clear `tls.serverName`.
If `endpoint` is still the default `:443`, the chart rewrites it to `:80`.

### Admission webhook

The controller serves a validating admission webhook for
`WorkloadNetworkPolicy`. It rejects a `WorkloadNetworkPolicy` whose
`(targetRef, direction)` is already taken in the same namespace.

### Scheduling

The `global` block sets `tolerations`, `nodeSelector`, `affinity`, and the
other scheduling keys for all workloads. The `controller` and
`controller.provider.istio.agent` blocks accept the same keys. A value in a
workload block replaces the value in `global`.

The ztunnel log reader reads logs from the node's filesystem and needs a pod
on every node running Istio's ambient `ztunnel` DaemonSet, including tainted
nodes such as control-plane nodes. Its default `Exists` toleration matches
ztunnel, but custom tolerations, node selectors, or affinity can leave ztunnel
nodes uncovered.

`controller.provider.istio.agent.tolerations` replaces
`common.tolerations` and `global.tolerations`. Set a workload's
tolerations to `[]` to fall back to `common.tolerations`, then
`global.tolerations`. If those are also empty, the workload no longer tolerates
taints and cannot collect logs from ztunnel on tainted nodes.

The log reader uses the chart's high-priority shared PriorityClass and may
preempt lower-priority pods. See `controller.provider.istio.agent.resources`
in [`values.yaml`](https://github.com/kubewarden/network-enforcer/blob/main/charts/network-enforcer/values.yaml)
for the current resource requests and limits.

The `controller` Deployment has no tolerations by default. Set
`controller.tolerations` or `global.tolerations` to schedule it onto tainted
nodes.

### ztunnel log reader

The ztunnel log reader is Network Enforcer's per-node agent, not Istio's own
`istio-agent` component. It is configured under `controller.provider.istio.agent`.
The image repository, binary, resource names, and discovery labels use the
`agent` name; image tags are release-managed with the controller.

On the Istio `ztunnel` chart, set `logAsJson=true` so the agent can read the logs.
Set `env.AUTHZ_POLICY_INFO_LOGGING=true` so ztunnel logs authorization decisions.
For monitor mode, set `pilot.env.AMBIENT_ENABLE_DRY_RUN_AUTHORIZATION_POLICY=true`
on the `istiod` chart with `profile=ambient`.

By default, the controller leader polls each agent pod IP over gRPC on port
`50052`. Each agent holds up to 10,000 events in memory. New events replace the
oldest ones when the buffer fills. Restarting the agent clears the buffer.
A scrape drains the buffer before the agent replies. If the reply is lost, the
agent cannot send those events again.

#### Log access and security

The log reader runs as root and accepts only
`/var/log/pods/istio-system_ztunnel-*/ztunnel/*.log` and
`/var/log/pods/istio-system_ztunnel-*/istio-proxy/*.log`. It mounts only
`/var/log/pods` read-only using a `hostPath` `Directory` mount. It does
not mount a ServiceAccount token and has no Kubernetes RBAC permissions.
The matcher excludes other namespaces, misleading pod names, all other container
names, and rotated filenames.

The `.log` suffix excludes retained `.log.<timestamp>`, `.log.gz`, and `.log.tmp`
rotations. An already-open renamed log receives a best-effort one-pass drain;
writes arriving after that drain and before the producer reopens a matching
`.log` may be lost. This protects against ordinary tenant log spoofing, not node
root, privileged writers, or control of trusted ztunnel workloads. A compromised
log reader can still read other logs exposed by its host mounts. No chart
NetworkPolicy restricts the agent port.

> [!WARNING]
> The ztunnel log reader is **not compatible with the restricted Pod Security Standard**.
> It runs as root and uses hostPath, which also violates baseline Pod Security.
> The release namespace's admission policy must explicitly permit the required
> hostPath and root settings (or exempt that namespace); changing only the UID
> cannot make this workload restricted-compatible. The chart does not change
> namespace Pod Security labels.

The container uses a read-only root filesystem, drops all capabilities, disables
privilege escalation, and uses `RuntimeDefault` seccomp. cert-manager's CSI driver
provides its per-pod mTLS identity.

#### Deployment and transport

Set `controller.provider.istio.agent.enabled: false` to disable only the
chart-managed DaemonSet. The controller still defaults to authenticated mTLS and
can ingest from externally managed agents that satisfy the existing namespace,
discovery-label selector, port, CA, certificate SAN, and client SAN contract.
Disabling the local DaemonSet does not provision those agents.

Both binaries enable mTLS by default; the chart does not pass redundant enable
flags. For local plaintext development, both sides must explicitly opt out:
`--grpc-mtls-enabled=false` on the agent and `--agent-grpc-mtls-enabled=false`
on the controller. Disabling only one side prevents ingestion. Agent `args` are
emitted before the chart-owned log matcher, port, certificate directory, and
client SAN flags, which remain pinned.

### Provider override example

```yaml
controller:
  provider:
    name: cilium
    cilium:
      tls:
        mode: insecure
        serverName: ""   # clear the Relay SAN override for plaintext
```

The controller binary stays provider-neutral: the chart renders `--provider-tls-*`
flags (including `--provider-tls-ca-bundle-key` when a CA ConfigMap is used).

See the comments in `values.yaml` for the full list of options.

### CRDs

CRDs are installed with the `helm.sh/resource-policy: keep` annotation:

- `helm upgrade` updates CRDs normally
- `helm uninstall` does not delete CRDs, which prevents cascade-deletion of all
  WorkloadNetworkPolicies and WorkloadNetworkPolicyProposals in the cluster

#### Reinstalling under a different release name or namespace

Because the CRDs are kept on uninstall, they survive with the Helm
ownership metadata of the release that created them
(`meta.helm.sh/release-name` and `meta.helm.sh/release-namespace`). Helm
checks this metadata on the next install:

- Same release name **and** namespace: Helm adopts the existing CRDs and
  the install succeeds.
- Different release name **or** namespace: Helm refuses to take over the
  CRDs and the install fails with:

  ```
  Error: ... invalid ownership metadata; annotation
  meta.helm.sh/release-name must equal "<new>": current value is "<old>"
  ```

This is expected: the CRDs still belong to the previous release. To adopt
them into the new release, install with `--take-ownership` (Helm 3.18+ or
Helm 4), which re-stamps the ownership metadata:

```sh
helm install <release> <chart> -n <namespace> --take-ownership
```

### Finding the low-level policies created by network-enforcer

Every `NetworkPolicy` and Istio `AuthorizationPolicy` rendered from a
`WorkloadNetworkPolicy` carries the `app.kubernetes.io/managed-by:
network-enforcer` label, so you can list them with a single selector:

```sh
kubectl get networkpolicies,authorizationpolicies -A \
  -l app.kubernetes.io/managed-by=network-enforcer
```

## Uninstall

```sh
helm uninstall network-enforcer --namespace network-enforcer
```

Note that this command won't delete the existing WorkloadNetworkPolicy and
WorkloadNetworkPolicyProposal resources.

To remove them, you can run the following commands:

```sh
kubectl delete crd workloadnetworkpolicies.networkenforcer.kubewarden.io
kubectl delete crd workloadnetworkpolicyproposals.networkenforcer.kubewarden.io
```

Finally, delete the namespace where Network Enforcer was deployed:

```sh
kubectl delete ns network-enforcer
```

# Software bill of materials & provenance

All Kubewarden components has its software bill of materials (SBOM) and build
[Provenance](https://slsa.dev/spec/v1.0/provenance) information published every
release. It follows the [SPDX](https://spdx.dev/) format and
[SLSA](https://slsa.dev/provenance/v0.2#schema) provenance schema.
Both of the files are generated by [Docker
buildx](https://docs.docker.com/build/metadata/attestations/) during the build
process and stored in the container registry together with the container image
as well as upload in the release page.

You can find them together with the signature and certificate used to sign it
in the [release
assets](https://github.com/kubewarden/network-enforcer/releases), and
attached to the image as JSON-encoded documents following the [in-toto SPDX
predicate](https://github.com/in-toto/attestation/blob/main/spec/predicates/spdx.md)
format. You can obtain them with
[`crane`](https://github.com/google/go-containerregistry/blob/main/cmd/crane/README.md)
or [`docker buildx imagetools
inspect`](https://docs.docker.com/reference/cli/docker/buildx/imagetools/inspect).

Network Enforcer publishes one image: `controller`. The release assets follow
the pattern
`NetworkEnforcer-controller-attestation-<arch>-<provenance|sbom>.<ext>`.

Network Enforcer signs the container image and the SBOM and provenance
files. The signatures use keyless signing with the GitHub Actions OIDC
identity of the shared `container-release.yml` reusable workflow in the
`kubewarden/github-actions` repository. The `@<ref>` part of that identity is
the commit of the reusable workflow, not the Network Enforcer tag, so the
commands match it with `--certificate-identity-regexp`. That identity alone names the
builder, not the release. The commands also pin the caller repository and the
release tag with `--certificate-github-workflow-repository` and
`--certificate-github-workflow-ref`, so a signed file from another repository
or another release does not pass. The flags do not bind the component. Every
component of one release shares these certificate values, so a blob and its
bundle from one component verify under another component's filename. To check
which image a file describes, read the `subject` field inside the file.

The same workflow runs `actions/attest` on the multi-architecture image. That
attestation gives the image SLSA Build L3. To verify it, run:

```shell
gh attestation verify oci://ghcr.io/kubewarden/network-enforcer/controller:<TAG TO VERIFY> \
    --repo kubewarden/network-enforcer \
    --signer-workflow kubewarden/github-actions/.github/workflows/container-release.yml
```

To verify the cosign signature of the image, run:

```shell
cosign verify --certificate-oidc-issuer=https://token.actions.githubusercontent.com  \
    --certificate-identity-regexp='^https://github\.com/kubewarden/github-actions/\.github/workflows/container-release\.yml@' \
    --certificate-github-workflow-repository=kubewarden/network-enforcer \
    --certificate-github-workflow-ref='refs/tags/<TAG TO VERIFY>' \
    ghcr.io/kubewarden/network-enforcer/controller:<TAG TO VERIFY>
```

The command works with a tag and with a digest. The release signs the
multi-architecture image and each single-architecture image.

To verify the provenance file from the release assets, run:

```shell
cosign verify-blob --certificate-oidc-issuer=https://token.actions.githubusercontent.com  \
    --certificate-identity-regexp='^https://github\.com/kubewarden/github-actions/\.github/workflows/container-release\.yml@' \
    --certificate-github-workflow-repository=kubewarden/network-enforcer \
    --certificate-github-workflow-ref='refs/tags/<TAG TO VERIFY>' \
    --bundle NetworkEnforcer-controller-attestation-amd64-provenance.intoto.jsonl.bundle.sigstore \
    NetworkEnforcer-controller-attestation-amd64-provenance.intoto.jsonl
```

To verify the SBOM file, use the same command with the `sbom.json` files:

```shell
cosign verify-blob --certificate-oidc-issuer=https://token.actions.githubusercontent.com  \
    --certificate-identity-regexp='^https://github\.com/kubewarden/github-actions/\.github/workflows/container-release\.yml@' \
    --certificate-github-workflow-repository=kubewarden/network-enforcer \
    --certificate-github-workflow-ref='refs/tags/<TAG TO VERIFY>' \
    --bundle NetworkEnforcer-controller-attestation-amd64-sbom.json.bundle.sigstore \
    NetworkEnforcer-controller-attestation-amd64-sbom.json
```

The SBOM and provenance files are also attached to the image in the registry.
Docker Buildx stores them in one attestation manifest per architecture. The
registry copy is not signed. The signed copies are the release assets.

To list the attestation manifests of a tag, run:

```shell
crane manifest ghcr.io/kubewarden/network-enforcer/controller:<TAG TO VERIFY> | jq '.manifests[] | select(.annotations["vnd.docker.reference.type"]=="attestation-manifest")'
```

Each attestation manifest has one layer per SBOM or provenance file. To list
the layers, run:

```shell
crane manifest ghcr.io/kubewarden/network-enforcer/controller@sha256:<ATTESTATION MANIFEST DIGEST>
```

To download one file, use the digest of its layer:

```shell
crane blob ghcr.io/kubewarden/network-enforcer/controller@sha256:<LAYER DIGEST>
```

## Security disclosure

See the [Kubewarden security policy](https://github.com/kubewarden/community/security/policy).

## Build with the community

Network Enforcer is part of [Kubewarden](https://www.kubewarden.io/), a CNCF
Sandbox project. Rancher by SUSE developed it first.

Get help, share an idea, or improve these docs.

- [Join us on Slack](https://kubernetes.slack.com/?redir=%2Fmessages%2Fkubewarden)
- [Community meetings](https://www.kubewarden.io/#get-in-touch)
- [Contribute to the docs](https://github.com/kubewarden/docs)

# Changelog

See [GitHub Releases content](https://github.com/kubewarden/network-enforcer/releases).
