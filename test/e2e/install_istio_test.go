package e2e_test

import (
	"context"
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	"sigs.k8s.io/e2e-framework/klient/k8s/resources"
	"sigs.k8s.io/e2e-framework/klient/wait"
	"sigs.k8s.io/e2e-framework/klient/wait/conditions"
	"sigs.k8s.io/e2e-framework/pkg/env"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/third_party/helm"
)

// installIstioMesh installs an Istio ambient mesh using the official Istio
// Helm charts, in dependency order:
//
//  1. istio/base   — cluster-wide CRDs
//  2. istio/istiod — control plane (pilot), with ambient and authz dry-run support
//  3. istio/cni    — chained CNI node agent, required to redirect ambient
//     workloads' traffic to the per-node ztunnel
//  4. istio/ztunnel — node-level L4 proxy that produces the access logs
//     network-enforcer consumes for learning/monitor/protect
//
// Each chart is installed with --wait so failures are attributable to a single
// component. The version is pinned to match the setup validated in RFC 0004.
func installIstioMesh() env.Func {
	return func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		manager := helm.New(cfg.KubeconfigFile())
		if err := addLocalChartRepo(ctx, manager, istioRepoLocalName, istioRepoURL); err != nil {
			return ctx, err
		}

		logger := getSetupLogger(ctx)
		charts := []struct {
			releaseName string
			chart       string
			args        []string
		}{
			{
				releaseName: "istio-base",
				chart:       istioRepoLocalName + "/base",
				args: []string{
					"--set", "defaultRevision=default",
				},
			},
			{
				releaseName: "istiod",
				chart:       istioRepoLocalName + "/istiod",
				args: []string{
					"--set", "profile=ambient",
					// observe monitor-mode (dry-run) authorization decisions in ztunnel logs
					"--set", "pilot.env.AMBIENT_ENABLE_DRY_RUN_AUTHORIZATION_POLICY=true",
				},
			},
			{
				releaseName: "istio-cni",
				chart:       istioRepoLocalName + "/cni",
				args: []string{
					"--set", "profile=ambient",
				},
			},
			{
				releaseName: "ztunnel",
				chart:       istioRepoLocalName + "/ztunnel",
				args: []string{
					// surface monitor-mode policy decisions in ztunnel logs
					"--set", "env.AUTHZ_POLICY_INFO_LOGGING=true",
					// emit logs as JSON: the istio-fluent-bit pipeline (ztunnel_json
					// parser + Lua) expects the flat dotted-key JSON format
					"--set", "logAsJson=true",
				},
			},
		}

		for _, c := range charts {
			opts := []helm.Option{
				helm.WithName(c.releaseName),
				helm.WithNamespace(istioNamespace),
				helm.WithChart(c.chart),
				helm.WithVersion(istioChartVersion),
				helm.WithArgs("--create-namespace"),
				helm.WithWait(),
				helm.WithTimeout(defaultHelmTimeout.String()),
			}
			for _, arg := range c.args {
				opts = append(opts, helm.WithArgs(arg))
			}
			logger.InfoContext(ctx, "🛠️ installing istio chart",
				"release", c.releaseName, "chart", c.chart, "version", istioChartVersion)
			if err := manager.RunInstall(opts...); err != nil {
				return ctx, fmt.Errorf("install %s chart: %w", c.releaseName, err)
			}
		}

		r, err := resources.New(cfg.Client().RESTConfig())
		if err != nil {
			return ctx, fmt.Errorf("create resources client: %w", err)
		}

		logger.InfoContext(ctx, "⏲️ waiting for istiod")
		if err = wait.For(
			conditions.New(r).DeploymentAvailable("istiod", istioNamespace),
			wait.WithTimeout(defaultOperationTimeout),
		); err != nil {
			return ctx, fmt.Errorf("wait istiod deployment ready: %w", err)
		}

		// ztunnel and istio-cni run as DaemonSets. Every node must be ready
		// before we deploy test workloads, otherwise a pod created before the
		// CNI node agent is ready on its node would bypass the mesh entirely.
		// (the istio-cni chart names its DaemonSet "istio-cni-node").
		for _, dsName := range []string{"ztunnel", "istio-cni-node"} {
			logger.InfoContext(ctx, "⏲️ waiting for "+dsName)
			if err = wait.For(
				conditions.New(r).DaemonSetReady(&appsv1.DaemonSet{
					Name: dsName, Namespace: istioNamespace,
				}),
				wait.WithTimeout(defaultOperationTimeout),
			); err != nil {
				return ctx, fmt.Errorf("wait %s daemonset ready: %w", dsName, err)
			}
		}

		return ctx, nil
	}
}
