# Contributing

## Code conventions

Read our global [CONTRIBUTING
guidelines](https://github.com/kubewarden/community/blob/main/CONTRIBUTING.md)
and the [AI usage
policy](https://github.com/kubewarden/community/blob/main/AI_POLICY.md).

## Requirements

You need the following tools to build and run this project:

- **Docker**: for building and running containerized workloads.
- **Go**: required by all the components. The exact version is defined in `go.mod`.
- **A C compiler** (`gcc` or equivalent): required by the Go race detector
  that `make test` uses.
- **[protoc](https://grpc.io/docs/protoc-installation/)**: required to
  regenerate the Calico Goldmane gRPC client.
- **Make**: the build tool controlling various build tasks.
- **[Tilt](https://docs.tilt.dev/)**: a development tool for multi-service applications.
- **[kind](https://kind.sigs.k8s.io/)**: creates the local Kubernetes
  clusters used for development and for the e2e tests.
- **[kubectl](https://kubernetes.io/docs/reference/kubectl/)**: the Kubernetes command line tool.
- **[Helm](https://helm.sh/)**: required for deploying and testing charts. The
  chart tests need the
  [helm-unittest](https://github.com/helm-unittest/helm-unittest) plugin.
- **[pre-commit](https://pre-commit.com/)**: runs all the linters.

The following tools are optional:

- **Node.js**: required to run [commitlint](https://commitlint.js.org/) on
  your machine.

## Code Layout

The repository has the following layout:

- `api`: the Go types of the `WorkloadNetworkPolicy` and
  `WorkloadNetworkPolicyProposal` CRDs (custom resource definitions).
- `charts`: contains the Helm chart for managing deployments.
- `cmd/controller`: the main entry point of the controller executable.
- `docs`: the generated CRD reference and the RFCs.
- `hack`: helper scripts and the Dockerfile used by Tilt.
- `internal`: the private Go implementation packages used by the controller.
  The `internal/scraper` package holds one flow scraper per provider (Istio
  ambient, Calico Goldmane, Cilium Hubble).
- `package`: the Dockerfile of the released container image.
- `test/e2e`: end-to-end tests. A real Kubernetes cluster is created using Docker and kind.
- `updatecli`: the automation that bumps dependencies and the Helm chart.

## Linting and Formatting

All the linters run through [pre-commit](https://pre-commit.com/). The
`.pre-commit-config.yaml` file defines them. CI runs the same hooks.

Install the hooks in your local clone:

```console
pre-commit install --install-hooks
```

Run all the linters on all the files:

```console
pre-commit run --all-files
```

Format Go code:

```console
make fmt
```

Run `go vet`:

```console
make vet
```

Run the Go linter ([golangci-lint](https://golangci-lint.run/)). The target
downloads the pinned version into `bin/` and builds it with the custom plugins
defined in `.custom-gcl.yml`:

```console
make lint
```

Fix the issues that the linter can fix by itself:

```console
make lint-fix
```

## Building

Build the controller binary:

```console
make controller
```

Make writes the binary to `bin/controller`.

Build the controller container image:

```console
make build-controller-image
```

You can customize the repository and the tag using environment variables:

```console
make build-controller-image REPO=ghcr.io/your-username/network-enforcer TAG=dev
```

## Development

To run the controller for development purposes, you can use
[Tilt](https://tilt.dev/).

### Settings

The `tilt-settings.yaml.example` acts as a template for the
`tilt-settings.yaml` file that you need to create in the root of this
repository. Copy the example file and edit it to match your environment. Git
ignores the `tilt-settings.yaml` file, so you cannot commit it by mistake.

The file accepts the following keys:

- `clusters`: the list of Kubernetes contexts that Tilt can use. Add one entry
  per kind cluster that you create with `make setup-dev-cluster`.
- `controller.image`: the name of the controller image.
- `controller.providerName`: the default data-plane provider. The accepted
  values are `istio`, `calico` and `cilium`. The `--provider` flag of
  `tilt up` overrides this value.

Example:

```yaml
clusters:
  - kind-istio
  - kind-calico
  - kind-cilium
controller:
  image: controller
  providerName: "istio"
```

### Running

The `Tiltfile` included in this repository takes care of the following:

- Creates the `network-enforcer` namespace.
- Installs the `network-enforcer` Helm chart from the `charts` folder, with the
  selected provider and the flow dumper enabled.
- Rebuilds the controller binary and reloads it inside the running Pod on
  every code change.

The controller needs a cluster with one of the supported providers and with
cert-manager installed. The `setup-dev-cluster` target creates a kind cluster,
installs the provider and cert-manager, and then starts Tilt. `E2E_PROVIDER`
selects the provider (`istio`, `calico` or `cilium`):

```console
make setup-dev-cluster E2E_PROVIDER=istio
```

The web interface of Tilt is at http://localhost:10350. Use it to monitor the
log stream of the controller and to trigger restarts by hand.

By default the target creates a kind cluster named `kind`. Set `CLUSTER_NAME`
to keep one persistent cluster per provider:

```console
make setup-dev-cluster E2E_PROVIDER=istio  CLUSTER_NAME=istio
make setup-dev-cluster E2E_PROVIDER=calico CLUSTER_NAME=calico
make setup-dev-cluster E2E_PROVIDER=cilium CLUSTER_NAME=cilium
```

The kind cluster name maps to the kubeconfig context `kind-<CLUSTER_NAME>`.
Add each context to the `clusters` list in `tilt-settings.yaml`.

Only one Tilt instance can run at a time on the default port. To switch
cluster, stop Tilt with `Ctrl-C` and run `setup-dev-cluster` again with the
other `CLUSTER_NAME`.

Make sure that the controller is up:

```console
kubectl get pods -n network-enforcer
kubectl get workloadnetworkpolicyproposals.networkenforcer.kubewarden.io -A
```

When you are done, stop Tilt and delete the cluster. Pass the same
`CLUSTER_NAME` that you used above:

```console
make delete-dev-cluster
make delete-dev-cluster CLUSTER_NAME=istio
```

## Changes to CRDs and other generated code

After changing a CRD, the RBAC markers of the controller or the Helm chart
`values.yaml`, run the following command:

```console
make generate
```

This will:

- Update all the generated Go code
- Update the CRDs and the RBAC rules shipped by our Helm chart
- Update the CRD reference in `docs/crds/CRD-docs-for-docs-repo.adoc`
- Update the `values.schema.json` of the Helm chart

To update only the CRD reference:

```console
make generate-crd-docs
```

CI runs `make generate` on each pull request. If the generated files are not up
to date, CI fails.

### Calico Goldmane gRPC client

The Calico scraper talks to Goldmane, the flow aggregator of Calico, over
gRPC. The `.proto` file and the generated Go code live in
`internal/scraper/goldmane`. When the Goldmane API changes, download the new
`.proto` file and regenerate the Go code. `protoc` must be on your `PATH`.
`GOLDMANE_VERSION` is the Calico version, the same one used by the e2e tests:

```console
make generate-calico-goldmane-proto GOLDMANE_VERSION=v3.32.1
```

Override `GOLDMANE_VERSION` only when you bump Calico.

## Testing

### Running Tests

Run all unit tests:

```console
make test
```

The target downloads the envtest binaries into `bin/` on the first run. It
runs every package except `test/e2e`.

Run e2e tests against the provider of your choice (`istio`, `calico` or
`cilium`):

```console
make test-e2e E2E_PROVIDER=istio
```

The target builds the controller image, creates a kind cluster, installs the
provider, cert-manager and the chart, and runs the tests. The following
environment variables change this behavior:

- `E2E_USE_EXISTING_CLUSTER=true`: use the cluster of your current kubeconfig
  instead of creating a kind cluster. Make does not rebuild the image.
- `E2E_NO_REBUILD=true`: do not rebuild the controller image.
- `E2E_DEPENDENCIES=none`: do not install the provider and cert-manager. Use
  this with an existing cluster that already has them.

CAUTION: Run the e2e tests against a dedicated kind cluster. The tests
install and remove cluster-wide components.

### Helm Chart Tests

Run Helm chart unit tests:

```console
make helm-unit-test
```

The tests are in `charts/network-enforcer/tests`.

### Writing tests

The Go unit tests use the standard `testing` package and
[testify](https://github.com/stretchr/testify).

The controller tests run with
[envtest](https://book.kubebuilder.io/reference/envtest). envtest starts an
instance of etcd and the Kubernetes API server, without kubelet,
controller-manager, or other components.

Some tests require a real Kubernetes cluster to run. These tests are in the
`test/e2e` folder and use the
[e2e-framework](https://github.com/kubernetes-sigs/e2e-framework).

The suite setup starts a cluster with [kind](https://kind.sigs.k8s.io/) and
runs the tests against it. When the tests finish, the suite deletes the
cluster.

The `e2e` tests are slower than the `envtest` tests. As a result, keep their
number to a minimum.

## Commit subjects

The commit messages must follow the [conventional commits
standard](https://www.conventionalcommits.org/en/v1.0.0/). For example:

- `type: free form subject`

Common `type` values include:

- `feat`: a commit that introduces a new feature
- `fix`: a commit that fixes an issue
- `perf`: a commit that improves performance
- `refactor`: a commit that refactors some code

Some examples:

- `feat: this is a new feature`
- `fix: this is fixing a reported bug`

You can also specify a component if this commit targets one component
specifically.

- `feat(scraper): add support for a new provider`

CI runs [commitlint](https://commitlint.js.org/) on the commits of each pull
request. The rules are in `commitlint.config.js`. To run commitlint on your
machine:

```console
npm ci
npx commitlint --from main
```

## Releasing

The [release issue
template](.github/ISSUE_TEMPLATE/3-network-enforcer-release.yml) documents the
release process. Open a new issue from that template to track a release. The
[release workflow](.github/workflows/release.yml) starts when you push a
`v*.*.*` tag.

## Additional Resources

- **Developer Documentation**: The `docs/crds` folder contains the generated
  CRD reference (`CRD-docs-for-docs-repo.adoc`) and the tooling that produces
  it.
- **RFCs**: The `docs/rfc` folder holds design proposals and architectural
  decisions.
- **User Documentation**: The user documentation is at
  [docs.kubewarden.io](https://docs.kubewarden.io/network-enforcer/latest/en/introduction.html).
  Its source is in the [kubewarden/docs](https://github.com/kubewarden/docs)
  repository.
