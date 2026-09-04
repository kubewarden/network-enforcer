|              |                                                                 |
| :----------- | :-------------------------------------------------------------- |
| Feature Name | Monitor/Protect policy lifecycle                                |
| Start Date   | 2026-06-26                                                      |
| Category     | Architecture                                                    |
| RFC PR       | https://github.com/kubewarden/network-enforcer/pull/40     |
| State        | **ACCEPTED**                                                    |

# Summary

This RFC introduces explicit runtime policy modes in `network-enforcer` by adopting the same Proposal -> Policy pattern used by `runtime-enforcer`.

The design defines two CRDs:

- `WorkloadNetworkPolicyProposal`: the learning output (observed intent). This is the current proposal renamed from `NetworkPolicyProposal` to `WorkloadNetworkPolicyProposal`
- `WorkloadNetworkPolicy`: the runtime policy with `spec.mode`

Promotion from proposal to policy is explicit. The monitor phase is implemented initially by reusing learning flows in a best-effort way. This means that the monitor phase is not enforced by the underlying CNI and may not catch all violations.

# Motivation

The current implementation can only create enforceable Kubernetes `NetworkPolicy` resources from proposals and cannot represent a first-class "monitor-only" policy.

Issue [#32](https://github.com/kubewarden/network-enforcer/issues/32) and team discussions highlighted two points:

- We want monitor mode in the MVP.
- CNI-native monitor/audit capabilities are not consistently available across all CNIs and environments.

Given the above points, the short-term path is to reuse learning telemetry for monitor violations, while keeping a clean API and lifecycle that can evolve toward more precise CNI-native monitoring later.

## Examples / User Stories

- Users review a learned `WorkloadNetworkPolicyProposal` and explicitly promotes it.
- Promotion creates a `WorkloadNetworkPolicy` in `monitor` mode and removes the proposal.
- In monitor mode, newly observed flows that are not allowed by the policy are reported as violations (best effort), without enforcing data-plane drops.
- When the owner flips mode to `protect`, the controller creates and keeps in sync a real Kubernetes `NetworkPolicy`. In the future it could be a CNI specific policy but for now we just use the standard Kubernetes `NetworkPolicy`.
- When the owner flips mode back to `monitor`, the Kubernetes `NetworkPolicy` is deleted.

# Detailed design

## Goals

- Introduce first-class `monitor` and `protect` runtime modes
- Keep an explicit Proposal -> Policy workflow
- Align naming and lifecycle with `runtime-enforcer`
- Avoid naming collisions with core Kubernetes `NetworkPolicy`

## Non-goals

- Building a CNI-native monitor backend in this first iteration

## API surface

### `WorkloadNetworkPolicyProposal`

Rename of the current `NetworkPolicyProposal`. We need a rename to have a naming convention that aligns with the new `WorkloadNetworkPolicy` resource. `WorkloadNetworkPolicyProposal` -> `WorkloadNetworkPolicy`. This is very similar to what we have in the runtime-enforcer `WorkloadPolicyProposal` -> `WorkloadPolicy`

Purpose:

- Learning output generated from observed traffic
- Candidate policy awaiting explicit promotion

Approval label:

- `networkenforcer.kubewarden.io/policy-ready=true`, mirroring the label used in the runtime-enforcer.

### `WorkloadNetworkPolicy`

New runtime policy CR.

- `spec.mode`: `monitor | protect`
- `spec.policy`: `networkingv1.NetworkPolicySpec`

Example:

```yaml
apiVersion: networkenforcer.kubewarden.io/v1alpha1
kind: WorkloadNetworkPolicy
metadata:
  name: deployment-nginx-egress
  namespace: default
  labels:
    networkenforcer.kubewarden.io/promoted-from: deployment-nginx-egress
spec:
  mode: monitor # monitor|protect
  policy:
    podSelector:
      matchLabels:
        app: nginx
    policyTypes:
      - Egress
    egress:
      - to:
          - namespaceSelector:
              matchLabels:
                kubernetes.io/metadata.name: default
            podSelector:
              matchLabels:
                app: postgres
        ports:
          - protocol: TCP
            port: 5432
```

In this first design no status is populated. In the future we could add violations like in the runtime-enforcer.

## Controller responsibilities

### 1) `WorkloadNetworkPolicyProposalReconciler`

This reconciler handles explicit proposal promotion.

Flow:

1. Watch `WorkloadNetworkPolicyProposal`
2. If object is deleting: no-op
3. If a `WorkloadNetworkPolicy` already exists with `networkenforcer.kubewarden.io/promoted-from=<proposal-name>`, treat the proposal as leftover and delete it.
4. If `networkenforcer.kubewarden.io/policy-ready=true` is not present: no-op.
5. Create `WorkloadNetworkPolicy` with:
   - same name/namespace
   - `spec.mode=monitor`
   - `spec.policy` copied from proposal spec
   - `promoted-from` label set
6. On successful creation, delete the proposal

This behavior intentionally mirrors `runtime-enforcer`'s `WorkloadPolicyProposalReconciler`.

### 2) Topology scanner

The scanner remains the learning producer, but now gates proposal creation based on runtime policy presence.

For each workload + direction:

1. Check whether a `WorkloadNetworkPolicy` exists for that target (including `promoted-from` semantics to avoid recreate races)
2. If policy exists and `mode=monitor`:
   - evaluate new flows against `spec.policy`
   - emit monitor violation when a flow would be denied. It could be an otel log.
   - do not create a new proposal. When a policy exists the proposal should be already deleted and should not be recreated.
3. If policy exists and `mode=protect`:
   - do nothing. The cni-watcher will report violations.
4. If no policy exists:
   - create or update `WorkloadNetworkPolicyProposal`

### 3) `WorkloadNetworkPolicyReconciler`

New reconciler for runtime policy enforcement.

Watch:

- `WorkloadNetworkPolicy` create/update/delete

Behavior:

- If `spec.mode=protect`:
  - create Kubernetes `networking.k8s.io/NetworkPolicy` if missing
  - update Kubernetes `NetworkPolicy` if spec changes
- If `spec.mode=monitor`:
  - ensure Kubernetes `NetworkPolicy` is absent (delete if present)

## Naming decision

Adopt:

- `WorkloadNetworkPolicyProposal`
- `WorkloadNetworkPolicy`

Rationale:

- Preserves Proposal -> Policy pattern
- Avoids collision with Kubernetes `NetworkPolicy`
- Uniforms naming with `runtime-enforcer`'s `WorkloadPolicyProposal` and `WorkloadPolicy`

# Alternatives

- Use CNI-native monitor only: rejected for now due to inconsistent support and longer delivery timeline
