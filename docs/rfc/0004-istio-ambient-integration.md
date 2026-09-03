|              |                                                                  |
| :----------- | :--------------------------------------------------------------- |
| Feature Name | Istio-first provider model for learn/monitor/protect             |
| Start Date   | 2026-08-06                                                       |
| Category     | Architecture                                                     |
| RFC PR       | <https://github.com/kubewarden/network-enforcer/pull/204>   |
| State        |                                                                  |

## Summary

This RFC proposes moving `network-enforcer` to an Istio-first architecture for the full `learn` -> `monitor` -> `protect` lifecycle, using ambient mesh and `AuthorizationPolicy` as the primary path.

At the same time, we need a path for clusters where Istio is not the chosen data plane. Calico and Cilium already expose rich gRPC APIs that can support learn/monitor/protect without routing traffic through Istio.

This RFC aligns these two needs: Istio-first by default, native provider options for Calico/Cilium when Istio is not present.

## Investigation basis

The design in this RFC is based on hands-on validation

### Setup

```bash
minikube start --driver=kvm2  --nodes 2 --container-runtime=containerd

# Install istioctl
#
# curl -L https://istio.io/downloadIstio | sh -
# cd istio-1.30.3/bin
# chmod +x istioctl
./istioctl install --set profile=ambient \
  --set values.cni.ambient.ipv6=false \
  --set values.pilot.env.AMBIENT_ENABLE_DRY_RUN_AUTHORIZATION_POLICY=true \
  --set values.ztunnel.env.AUTHZ_POLICY_INFO_LOGGING=true \
  --skip-confirmation

# Install application
kubectl apply -f - <<EOF
apiVersion: v1
kind: ServiceAccount
metadata:
  name: http-server-sa
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: http-client-sa
---
apiVersion: v1
kind: Service
metadata:
  name: http-service
spec:
  selector:
    app: http-server
  ports:
    - name: tcp-echo
      protocol: TCP
      port: 18080
      targetPort: 18080
    - name: udp-echo
      protocol: UDP
      port: 18081
      targetPort: 18081
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: http-server
spec:
  replicas: 1
  selector:
    matchLabels:
      app: http-server
  template:
    metadata:
      labels:
        app: http-server
    spec:
      serviceAccountName: http-server-sa
      nodeSelector:
        kubernetes.io/hostname: minikube-m02
      containers:
        - name: http-server
          image: nicolaka/netshoot:v0.16
          command:
            - sh
            - -c
            - |
              set -eu
              # start TCP listener
              socat -d -d TCP-LISTEN:18080,reuseaddr,fork EXEC:/bin/cat >/tmp/tcp-listener.log 2>&1 &
              # start UDP listener
              socat -d -d UDP-RECVFROM:18081,reuseaddr,fork EXEC:/bin/cat >/tmp/udp-listener.log 2>&1 &
              wait
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: http-client
spec:
  replicas: 1
  selector:
    matchLabels:
      app: http-client
  template:
    metadata:
      labels:
        app: http-client
    spec:
      serviceAccountName: http-client-sa
      containers:
        - image: nicolaka/netshoot:v0.16
          name: http-client
          command: ["sleep", "10d"]
      nodeSelector:
        kubernetes.io/hostname: minikube
EOF

# Enroll the namespace in the mesh
kubectl label namespace default istio.io/dataplane-mode=ambient
```

### Learn mode

#### Destination outside the mesh

```bash
kubectl exec deployments/http-client -it -- curl http://google.com
```

The flow appears only in the source ztunnel because the destination is outside the mesh. In this case we only get the raw destination IP because the destination is outside the cluster.

```txt
2026-08-03T15:47:26.637407Z info access connection complete src.addr=10.244.0.5:54646 src.workload="http-client-6b4b85489f-t6sl2" src.namespace="default" dst.addr=142.251.209.46:80 direction="outbound" bytes_sent=74 bytes_recv=773 duration="357ms"
```

To observe the logs reported in this document, it is enough to scrape ztunnel logs on both nodes.

```bash
# Replace your ztunnel names
kubectl logs -n istio-system ztunnel-wwjv9 -f
kubectl logs -n istio-system ztunnel-zhks8 -f
```

#### Source outside the mesh

Create a deployment outside the mesh (istio-system namespace is outside the mesh)

```bash
kubectl apply -n istio-system -f - <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: client
spec:
  replicas: 1
  selector:
    matchLabels:
      app: client
  template:
    metadata:
      labels:
        app: client
    spec:
      containers:
        - image: nicolaka/netshoot:v0.16
          name: client
          command: ["sleep", "10d"]
EOF
kubectl exec -n istio-system deployments/client -it -- sh -c 'printf send-tcp-traffic | nc -w 1 http-service.default.svc.cluster.local 18080'
```

We see the source name and namespace but not SPIFFE identity since the source is outside the mesh.

```txt
2026-08-04T13:47:13.103969Z info access connection complete src.addr=10.244.0.17:34010 src.workload="client" src.namespace="istio-system" dst.addr=10.244.1.15:18080 dst.service="http-service.default.svc.cluster.local" dst.workload="http-server-6cbcc86f5d-bxb9w" dst.namespace="default" direction="inbound" bytes_sent=16 bytes_recv=16 duration="1004ms"
```

#### Both workloads inside the mesh

```bash
kubectl exec deployments/http-client -it -- sh -c 'printf send-tcp-traffic | nc -w 1 http-service 18080'
```

On the source ztunnel, direction is `outbound`.

```txt
2026-08-03T15:48:10.439059Z info access connection complete src.addr=10.244.0.5:40516 src.workload="http-client-6b4b85489f-t6sl2" src.namespace="default" src.identity="spiffe://cluster.local/ns/default/sa/http-client-sa" dst.addr=10.244.1.5:15008 dst.hbone_addr=10.244.1.5:18080 dst.service="http-service.default.svc.cluster.local" dst.workload="http-server-6cbcc86f5d-lhq82" dst.namespace="default" dst.identity="spiffe://cluster.local/ns/default/sa/http-server-sa" direction="outbound" bytes_sent=16 bytes_recv=16 duration="1006ms"
```

On the destination ztunnel, direction is `inbound`.

```txt
2026-08-03T15:48:10.413052Z info access connection complete src.addr=10.244.0.5:34704 src.workload="http-client-6b4b85489f-t6sl2" src.namespace="default" src.identity="spiffe://cluster.local/ns/default/sa/http-client-sa" dst.addr=10.244.1.5:15008 dst.hbone_addr=10.244.1.5:18080 dst.service="http-service.default.svc.cluster.local" dst.workload="http-server-6cbcc86f5d-lhq82" dst.namespace="default" dst.identity="spiffe://cluster.local/ns/default/sa/http-server-sa" direction="inbound" bytes_sent=16 bytes_recv=16 duration="1004ms"
```

The above logs are almost identical what changes is the direction of the traffic seen by each ztunnel.

#### Both workloads inside the mesh (UDP)

```bash
kubectl exec deployments/http-client -it -- sh -c 'printf send-udp-traffic | nc -u -w 1 http-service 18081'
```

No logs are produced because UDP traffic does not go through ztunnels.

### Monitor mode

#### Ingress deny

```bash
kubectl apply -f - <<EOF
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: deny-http-server-monitor
  annotations:
    istio.io/dry-run: "true"
spec:
  selector:
    matchLabels:
      app: http-server
  action: DENY
  rules:
    - from:
        - source:
            principals:
              - cluster.local/ns/default/sa/http-client-sa
      to:
        - operation:
            ports: ["18080"]
EOF
kubectl exec deployments/http-client -it -- sh -c 'printf send-tcp-traffic | nc -w 1 http-service 18080'
kubectl delete authorizationpolicies.security.istio.io deny-http-server-monitor
```

On the source ztunnel everything looks normal (like no policy is applied)

```txt
2026-08-03T15:34:58.755583Z info access connection complete src.addr=10.244.0.5:46014 src.workload="http-client-6b4b85489f-t6sl2" src.namespace="default" src.identity="spiffe://cluster.local/ns/default/sa/http-client-sa" dst.addr=10.244.1.5:15008 dst.hbone_addr=10.244.1.5:18080 dst.service="http-service.default.svc.cluster.local" dst.workload="http-server-6cbcc86f5d-lhq82" dst.namespace="default" dst.identity="spiffe://cluster.local/ns/default/sa/http-server-sa" direction="outbound" bytes_sent=16 bytes_recv=16 duration="1010ms"
```

On the destination ztunnel we see an additional dry-run log with the policy name that would deny the traffic, because this is an explicit `DENY` rule.

```txt
2026-08-03T15:34:57.746680Z info state:proxy{wl=default/http-server-6cbcc86f5d-lhq82}:inbound{id=a050131fa769a20e255b9840bf445424 peer=10.244.0.5:49084} dry-run: deny policy match policy="default/deny-http-server-monitor"
2026-08-03T15:34:57.746710Z info state:proxy{wl=default/http-server-6cbcc86f5d-lhq82}:inbound{id=a050131fa769a20e255b9840bf445424 peer=10.244.0.5:49084} no allow policies, allow 
2026-08-03T15:34:58.752429Z info access connection complete src.addr=10.244.0.5:49084 src.workload="http-client-6b4b85489f-t6sl2" src.namespace="default" src.identity="spiffe://cluster.local/ns/default/sa/http-client-sa" dst.addr=10.244.1.5:15008 dst.hbone_addr=10.244.1.5:18080 dst.service="http-service.default.svc.cluster.local" dst.workload="http-server-6cbcc86f5d-lhq82" dst.namespace="default" dst.identity="spiffe://cluster.local/ns/default/sa/http-server-sa" direction="inbound" bytes_sent=16 bytes_recv=16 duration="1005ms"
```

#### Ingress allow

```bash
kubectl apply -f - <<EOF
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: allow-http-server-monitor
  annotations:
    istio.io/dry-run: "true"
spec:
  selector:
    matchLabels:
      app: http-server
  action: ALLOW
  rules:
    - from:
        - source:
            principals:
              - cluster.local/ns/default/sa/another-client
      to:
        - operation:
            ports: ["18080"]
EOF
kubectl exec deployments/http-client -it -- sh -c 'printf send-tcp-traffic | nc -w 1 http-service 18080'
kubectl delete authorizationpolicies.security.istio.io allow-http-server-monitor
```

On the source side, behavior is unchanged from the `Ingress Deny`.

On the destination ztunnel, we don't see the name of the policy because no policy is explicitly denying the traffic. We can only see "no allow policies match"

```txt
2026-08-03T15:36:17.033568Z info state:proxy{wl=default/http-server-6cbcc86f5d-lhq82}:inbound{id=f03d939b04f8702eb7ad3a6281d793d5 peer=10.244.0.5:49084} dry-run: no allow policies match 
2026-08-03T15:36:17.033583Z info state:proxy{wl=default/http-server-6cbcc86f5d-lhq82}:inbound{id=f03d939b04f8702eb7ad3a6281d793d5 peer=10.244.0.5:49084} no allow policies, allow 
2026-08-03T15:36:18.038132Z info access connection complete src.addr=10.244.0.5:49084 src.workload="http-client-6b4b85489f-t6sl2" src.namespace="default" src.identity="spiffe://cluster.local/ns/default/sa/http-client-sa" dst.addr=10.244.1.5:15008 dst.hbone_addr=10.244.1.5:18080 dst.service="http-service.default.svc.cluster.local" dst.workload="http-server-6cbcc86f5d-lhq82" dst.namespace="default" dst.identity="spiffe://cluster.local/ns/default/sa/http-server-sa" direction="inbound" bytes_sent=16 bytes_recv=16 duration="1004ms"
```

### Protect mode

#### Ingress deny

```bash
kubectl apply -f - <<EOF
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: deny-http-server-protect
spec:
  selector:
    matchLabels:
      app: http-server
  action: DENY
  rules:
    - from:
        - source:
            principals:
              - cluster.local/ns/default/sa/http-client-sa
      to:
        - operation:
            ports: ["18080"]
EOF
kubectl exec deployments/http-client -it -- sh -c 'printf send-tcp-traffic | nc -w 1 http-service 18080'
kubectl delete authorizationpolicies.security.istio.io deny-http-server-protect
```

On the source side we see an unauthorized access error.

```txt
2026-08-03T15:39:07.560543Z error access connection complete src.addr=10.244.0.5:55480 src.workload="http-client-6b4b85489f-t6sl2" src.namespace="default" src.identity="spiffe://cluster.local/ns/default/sa/http-client-sa" dst.addr=10.244.1.5:15008 dst.hbone_addr=10.244.1.5:18080 dst.service="http-service.default.svc.cluster.local" dst.workload="http-server-6cbcc86f5d-lhq82" dst.namespace="default" dst.identity="spiffe://cluster.local/ns/default/sa/http-server-sa" direction="outbound" bytes_sent=0 bytes_recv=0 duration="0ms" error="http status: 401 Unauthorized"
```

On the destination side we see a rejection error with the policy name.

```txt
2026-08-03T15:39:07.536444Z info state:proxy{wl=default/http-server-6cbcc86f5d-lhq82}:inbound{id=86c37af8d376fcc847c48d4730137d42 peer=10.244.0.5:49084} deny policy match policy="default/deny-http-server-protect"
2026-08-03T15:39:07.536483Z error access connection complete src.addr=10.244.0.5:49084 src.workload="http-client-6b4b85489f-t6sl2" src.namespace="default" src.identity="spiffe://cluster.local/ns/default/sa/http-client-sa" dst.addr=10.244.1.5:15008 dst.hbone_addr=10.244.1.5:18080 dst.service="http-service.default.svc.cluster.local" dst.workload="http-server-6cbcc86f5d-lhq82" dst.namespace="default" dst.identity="spiffe://cluster.local/ns/default/sa/http-server-sa" direction="inbound" bytes_sent=0 bytes_recv=0 duration="0ms" error="connection closed due to policy rejection: explicitly denied by: default/deny-http-server-protect"
```

#### Ingress allow

```bash
kubectl apply -f - <<EOF
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: allow-http-server-protect
spec:
  selector:
    matchLabels:
      app: http-server
  action: ALLOW
  rules:
    - from:
        - source:
            principals:
              - cluster.local/ns/default/sa/another-client
      to:
        - operation:
            ports: ["18080"]
EOF
kubectl exec deployments/http-client -it -- sh -c 'printf send-tcp-traffic | nc -w 1 http-service 18080'
kubectl delete authorizationpolicies.security.istio.io allow-http-server-protect
```

On the source side we see an unauthorized access error.

```txt
2026-08-03T15:40:53.383263Z error access connection complete src.addr=10.244.0.5:52814 src.workload="http-client-6b4b85489f-t6sl2" src.namespace="default" src.identity="spiffe://cluster.local/ns/default/sa/http-client-sa" dst.addr=10.244.1.5:15008 dst.hbone_addr=10.244.1.5:18080 dst.service="http-service.default.svc.cluster.local" dst.workload="http-server-6cbcc86f5d-lhq82" dst.namespace="default" dst.identity="spiffe://cluster.local/ns/default/sa/http-server-sa" direction="outbound" bytes_sent=0 bytes_recv=0 duration="0ms" error="http status: 401 Unauthorized"
```

On the destination side we see a policy-rejection error, but without a policy name. This is the same thing we have seen in Monitor mode, no policy is explicitly denying the traffic, we only see "allow policies exist, but none allowed".

```txt
2026-08-03T15:40:53.359711Z info state:proxy{wl=default/http-server-6cbcc86f5d-lhq82}:inbound{id=d1622760126925234857353d59b402dc peer=10.244.0.5:49084} no allow policies matched 
2026-08-03T15:40:53.359734Z error access connection complete src.addr=10.244.0.5:49084 src.workload="http-client-6b4b85489f-t6sl2" src.namespace="default" src.identity="spiffe://cluster.local/ns/default/sa/http-client-sa" dst.addr=10.244.1.5:15008 dst.hbone_addr=10.244.1.5:18080 dst.service="http-service.default.svc.cluster.local" dst.workload="http-server-6cbcc86f5d-lhq82" dst.namespace="default" dst.identity="spiffe://cluster.local/ns/default/sa/http-server-sa" direction="inbound" bytes_sent=0 bytes_recv=0 duration="0ms" error="connection closed due to policy rejection: allow policies exist, but none allowed"
```

### Ingress gateway

```bash
kubectl get crd gateways.gateway.networking.k8s.io &> /dev/null || \
  kubectl apply --server-side -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.5.1/experimental-install.yaml

# Deploy the application
kubectl apply -f https://raw.githubusercontent.com/istio/istio/release-1.30/samples/bookinfo/platform/kube/bookinfo.yaml
kubectl apply -f https://raw.githubusercontent.com/istio/istio/release-1.30/samples/bookinfo/platform/kube/bookinfo-versions.yaml
# Deploy the gateway
kubectl apply -f https://raw.githubusercontent.com/istio/istio/release-1.30/samples/bookinfo/gateway-api/bookinfo-gateway.yaml
kubectl annotate gateway bookinfo-gateway networking.istio.io/service-type=ClusterIP --namespace=default
# Enroll the namespace in the mesh if necessary
kubectl label namespace default istio.io/dataplane-mode=ambient

# Port-forward the gateway
kubectl port-forward svc/bookinfo-gateway-istio 8080:80
# Access it from outside the cluster
http://localhost:8080/productpage
```

Here we only see the connection when it reaches the destination workload `productpage-v1` (`direction="inbound"`, so no `outbound` flow). This happens because the gateway is not part of the mesh (`istio.io/dataplane-mode=none`).
So we don't see the connection from external-ip -> gateway. We only see the connection from gateway -> productpage, when the traffic hits the inbound ztunnel.

```txt
2026-08-04T08:11:27.450747Z info access connection complete src.addr=10.244.1.9:47072 src.workload="bookinfo-gateway-istio-6fd954bf4-v2xsx" src.namespace="default" src.identity="spiffe://cluster.local/ns/default/sa/bookinfo-gateway-istio" dst.addr=10.244.1.7:15008 dst.hbone_addr=10.244.1.7:9080 dst.service="productpage.default.svc.cluster.local" dst.workload="productpage-v1-85664dccbc-dpfbp" dst.namespace="default" dst.identity="spiffe://cluster.local/ns/default/sa/bookinfo-productpage" direction="inbound" bytes_sent=409232 bytes_recv=4056 duration="2960ms"
```

### Practical conclusions from experiments

- Istio ambient gives strong identity and L4 policy semantics for in-mesh TCP.
- UDP is out of scope for this provider path.
- Enforcement is destination/inbound-centric.
- Attribution is excellent for explicit DENY, partial for ALLOW-miss outcomes.

## Detailed design

### Goals

- Make Istio the default provider for `learn`, `monitor`, and `protect`
- Support Calico and Cilium as first-class alternative providers through their gRPC APIs
- Preserve existing `WorkloadNetworkPolicyProposal` -> `WorkloadNetworkPolicy` lifecycle
- Keep violations and acknowledgements semantics stable across providers

### Provider model

`network-enforcer` exposes one logical lifecycle with pluggable provider implementations:

1. **Istio provider (default)**
   - Learning source: ztunnel logs
   - Monitor source: ztunnel logs + dry-run `AuthorizationPolicy` signals
   - Protect enforcement: Istio `AuthorizationPolicy`

2. **Calico provider (optional)** (not addressed in this RFC)
   - Learning/monitor/protect signals from Goldmane gRPC API

3. **Cilium provider (optional)** (not addressed in this RFC)
   - Learning/monitor/protect signals from Hubble gRPC API

The provider is configured at deployment time. The user-facing CRDs and promotion flow do not change.

### How Istio addresses OBI learning pain points

| OBI issue | Istio (ambient mode) |
| --- | --- |
| Learning UDP traffic is unreliable (based on port guessing) | UDP is generally outside ambient L4 scope, so UDP is treated as non-goal for this provider path. |
| Cross-node traffic resolution can be complex due to SNAT | In-mesh traffic includes workload identity context, reducing dependence on node IP correlation. |
| Duplicate OTel metrics per connection | Visibility is connection-log based (inbound/outbound views), with explicit control-plane deduplication. |
| Potential OTel metrics cardinality explosion | The Istio path does not depend on high-cardinality metrics for learning. Log volume remains a scaling concern. |

### L4 authorization policies limitations

- Istio L4 authorization policies are enforced only on inbound traffic at the destination ztunnel, not on egress: <https://istio.io/latest/docs/ambient/usage/l4-policy/#policy-enforcement-using-ztunnel>. This is a big difference with respect to traditional Kubernetes NetworkPolicies.
- They apply only to TCP traffic. UDP traffic does not pass through ztunnel, so no L4 policy can be enforced there.
- They rely on SPIFFE identity for policy matching. The identity is derived from the workload's ServiceAccount. So if a workload does not have a dedicated ServiceAccount, it will use the namespace default ServiceAccount, which can lead to overly permissive policies. -> We could have a KubeWarden policy to guide users to specify a service account for each workload as a best practice.
- There are scenarios where L4 policies are weak or not applicable:
  - Source pod outside the mesh and destination pod inside the mesh: we can define a policy on the destination, but the source has no SPIFFE identity. In practice, the only option is usually explicit `ipBlocks`, which is fragile.
  - Destination pod outside the mesh and source pod inside the mesh: we cannot enforce an L4 policy because enforcement is inbound-only and no destination ztunnel exists.

### Learning phase

- We can learn traffic if at least one endpoint is in the Istio mesh.
- To learn traffic, we read ztunnel logs (one ztunnel per node).
- We can learn only TCP traffic, because UDP bypasses ztunnel.
- Even when one endpoint is outside the mesh and traffic is observable, we often cannot produce a robust L4 policy (see limitations above), so we should avoid generating a proposal in those cases.
- We probably need to deduplicate traffic flows since we have 2 observations for the same connection (outbound and inbound). Keeping only the inbound observation is likely sufficient.

### Monitor phase

- We can derive monitor violations by scraping ztunnel logs.
- Policy name attribution is available only for explicit `DENY` matches (same limitation seen in Cilium). This is expected: with `ALLOW`-only policies, we can say that no policy matched, but not which specific policy blocked the traffic. A practical approach is to report the list of policies attached to the workload (similar to Calico). In our case, we usually have one policy per workload, so troubleshooting remains straightforward.
- The dry-run mode used for monitor is still alpha: <https://istio.io/latest/docs/tasks/security/authorization/authz-dry-run/>. Istio documentation also states: "The dry-run results in the proxy log, metric and tracing are for manual troubleshooting purposes and should not be used as an API because it may change anytime without prior notice." (<https://istio.io/latest/docs/tasks/security/authorization/authz-dry-run/#limitations>)

### Protect phase

- We can derive protect violations by scraping ztunnel logs.
- Policy name attribution is available only for explicit `DENY` matches (same limitation as monitor mode).
