|              |                                                     |
| :----------- | :-------------------------------------------------- |
| Feature Name | Violation/Policy correlation                        |
| Start Date   | 17 Sept. 2026                                       |
| Category     | API                                                 |
| RFC PR       | [fill this in after opening PR]                     |
| State        | **ACCEPTED**                                        |

## Summary

A violation must be recorded on the `WorkloadNetworkPolicy` (WNP) that governs the workload and direction it was observed on. Today the controller derives that association from label selectors, which are not a unique key: two WNPs can select the same pods. This RFC makes the association a declared, unique property of the API instead of something the controller guesses. A WNP gains `spec.targetRef` (the workload it governs) and `spec.direction`, at most one WNP may exist per `(namespace, targetRef, direction)`, and a WNP's rendered selector must select only pods belonging to its `targetRef`.

## Motivation

The learning pipeline already produces one proposal per `(workload, direction)`, so promoting both directions of a single Deployment yields two WNPs with byte-identical `podSelector`s. Correlation by selector cannot tell them apart: the Cilium path errors out and drops the violation, and the Istio path sorts the candidate names and takes the first one. Both outcomes are wrong in a security product. A dropped violation in protect mode shows the user "0 violations" on a policy that is denying traffic; a mis-attributed one corrupts the deduplication key, so the same flow can appear twice with two IDs on two objects, acknowledgements silence the wrong record, and `clearAllowedViolations` can never clear a violation whose allowing rule lives in the other WNP.

Attribution also decides which namespace's status displays a peer workload's identity, so getting it wrong is a confidentiality problem, not only a UX one. The deeper issue is that the question as posed has no answer: with allow-semantics policies and default deny, a denied flow is not caused by one policy but by the union of all policies selecting that workload in that direction. Rather than build a better tie-breaker for an ill-posed question, we constrain the API so the union is always a single object.

## Detailed design

`WorkloadNetworkPolicySpec` gains two required fields: `targetRef`, a `{kind, name}` pair restricted to `Deployment`, `StatefulSet` and `DaemonSet` and resolved in the WNP's own namespace, and `direction`, one of `Ingress` or `Egress` (Istio accepts `Ingress` only, since ztunnel enforces inbound). The `podSelector` keeps its current meaning as the selector rendered into the data-plane object, but it stops being an identity: admission rejects a WNP whose selector does not match the pod template labels of its `targetRef`. The learner and the proposal controller populate both fields, which they already hold. The controller registers a field index on `(targetRef.kind, targetRef.name, direction)`, so correlation becomes one indexed lookup instead of a namespace-wide `List` and a selector comparison per flow.

Resolving a flow's subject workload goes through pod `OwnerReferences` (pod to ReplicaSet to Deployment), which is unique per pod, so workloads sharing labels still resolve to distinct targets. Attribution follows a fixed chain: use the enforcing object reported by the data plane when there is one, verified against the existing ownership index and against the subject; otherwise the `targetRef` index; otherwise the violation is explicitly unattributed, counted in `network_enforcer_violations_unattributed_total` and still emitted as an OTel log. The subject workload is always the one the policy selects, never the peer, so external egress destinations remain attributable.

Because the reported enforcing object answers "which object enforced" and not "whose traffic was this", a reported policy whose owning WNP targets a workload other than the resolved subject is not trusted: the subject wins and the disagreement is counted, since it reliably indicates overlapping selectors.

Uniqueness of `(targetRef, direction)` fixes attribution but not enforcement scoping, because the rendered `NetworkPolicy` and `AuthorizationPolicy` still select pods by label. A WNP for a Deployment with `app=web` also selects the pods of a sibling Deployment with `app=web,tier=canary`, and since both backends union their allow rules per selected pod, the sibling silently gains rules nobody wrote for it. The worst case breaks the staged rollout of RFC 0003: a WNP in `protect` mode renders a data-plane object that enforces a sibling workload whose own WNP is still in `monitor`. Fully identical selectors across two workloads are already an unsupported configuration in Kubernetes, since the ReplicaSets adopt each other's pods, so the case to handle is partial overlap. This is the third invariant: a WNP's rendered selector must select only pods belonging to its `targetRef`. A webhook alone cannot hold it, because the conflict can appear later when another workload is created or relabelled, so the controller checks it on every reconciliation against the pod template labels of the other workloads in the namespace and sets `Ready=False` with `Reason=SelectorOverlapsWorkload`, naming the offending workload, plus a metric. The data-plane object is still rendered in that state, because refusing to render would leave the target unprotected, and violations continue to be attributed by subject.

Uniqueness is enforced in two places, because neither is sufficient alone. A validating webhook rejects a WNP whose `(targetRef, direction)` is already taken, naming the existing object in the error message; `failurePolicy: Fail` is scoped to this API group.

Since webhooks are not atomic against concurrent creates, and since clusters may already hold duplicates from before the upgrade, the controller also detects duplicates during reconciliation: all conflicting WNPs get `Ready=False` with `Reason=DuplicateTarget`, only the oldest by `creationTimestamp` (name as tie-break) renders a data-plane object, and violations for that workload and direction are reported as unattributed while the conflict lasts. Nothing is deleted retroactively. Finer-grained policy is expressed as multiple rules inside one WNP, not as multiple WNPs selecting the same workload.

## Drawbacks

Users lose the ability to layer policies, for example a platform-team baseline plus an app-team addition, on the same workload and direction; that has to be a single object with several rules. The project gains its first admission webhook, hence certificate plumbing in the chart, a `failurePolicy` decision and new e2e wiring, and a webhook outage blocks all WNP writes in this group. The overlap check needs the pod template labels of every workload in the namespace on each reconciliation, and it reports a condition for a situation the user may not be able to fix without relabeling a workload. Adding `direction` to the violation record key resets record IDs once on upgrade. This definitely needs a release note.

## Alternatives

Direction-aware selector matching alone fixes only the case the learner produces, and is included here as the first implementation step, not as the answer. A naming convention such as `deployment-frontend-ingress` as the canonical key puts semantics in strings, breaks on name-length limits and workload renames, and still permits a second overlapping WNP under a different name. A single WNP covering both directions removes the need for `direction` but destroys the per-direction staged rollout that RFC 0003 exists for, and still permits duplicates. For the scoping invariant, the stricter alternative is to stop copying the workload selector and render an exact one: the controller labels the target's pod template with `networkenforcer.kubewarden.io/target` and selects on that, which makes overlap structurally impossible but mutates user workloads and triggers a rollout on adoption. Recording the violation on every matching WNP is the honest reading of default-deny semantics, but it makes `violationCount` meaningless, requires N acknowledgements, and leaves phantom active violations behind.

## Unresolved questions

None.
