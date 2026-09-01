#!/usr/bin/env bash

set -eu

CILIUM_VERSION="${CILIUM_VERSION:-1.20.0}"
CILIUM_NAMESPACE="kube-system"

helm repo add cilium https://helm.cilium.io/
helm repo update

printf "\n- 🚀 Install cilium with Hubble and Hubble Relay:\n"
# Network-Enforcer scrapes flows from the Hubble Relay gRPC API, so both hubble
# and hubble.relay must be enabled.
#
# Relay server TLS is disabled: Network-Enforcer currently talks to
# hubble-relay.kube-system.svc:80 in plaintext.
# todo!: enable TLS for hubble relay
#
# policyDenyResponse=icmp makes cilium answer denied egress traffic with an ICMP
# error instead of silently dropping it.
helm upgrade --install cilium cilium/cilium \
  --version "$CILIUM_VERSION" \
  --namespace "$CILIUM_NAMESPACE" \
  --wait --timeout 10m \
  --set hubble.enabled=true \
  --set hubble.relay.enabled=true \
  --set hubble.relay.tls.server.enabled=false \
  --set policyDenyResponse=icmp

printf "\n- 🚀 Wait for cilium and Hubble Relay to be ready:\n"
kubectl rollout status daemonset/cilium -n "$CILIUM_NAMESPACE" --timeout=300s
kubectl rollout status deployment/cilium-operator -n "$CILIUM_NAMESPACE" --timeout=300s
kubectl rollout status deployment/hubble-relay -n "$CILIUM_NAMESPACE" --timeout=300s
