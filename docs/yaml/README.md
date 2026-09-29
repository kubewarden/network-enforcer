# Sample manifests

Kind / demo manifests for trying network-enforcer with Cilium or Calico.

| File | Purpose |
|------|---------|
| `kind_cluster.yaml` | Kind cluster with default CNI disabled (control-plane + worker). |
| `simple_application.yaml` | Client/server sample app for learning and violation demos. |

```bash
kind create cluster --name network-enforcer --config docs/yaml/kind_cluster.yaml
./hack/setup-cilium.sh   # or ./hack/setup-calico.sh
kubectl apply -f docs/yaml/simple_application.yaml
```
