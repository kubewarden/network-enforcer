package e2e_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"

	securityv1alpha1 "github.com/kubewarden/network-enforcer/api/v1alpha1"
)

const (
	// The suite installs the chart with a learning namespace selector that matches this label.
	learningNamespaceLabelKey   = "networkenforcer.kubewarden.io/e2e-learning"
	learningNamespaceLabelValue = "enabled"
	// The wait is longer than the provider flow export intervals and the Istio learning aggregation window.
	proposalIsNotCreatedTimeout = 30 * time.Second
)

func TestLearningNamespaceSelector(t *testing.T) {
	builder := features.New("Learning writes proposals only in namespaces that match the selector").
		Setup(setupTestNamespace).
		Setup(setLearningLabel(false))
	expectedProposals := []string{
		"deployment-" + simpleAppClientDeploymentName + "-egress",
		"deployment-" + simpleAppServerDeploymentName + "-ingress",
	}
	if loadSuiteConfig().IsIstioProvider() {
		builder = builder.Setup(labelNamespaceAmbient)
		// Istio enforces policies on the receiving side only.
		expectedProposals = expectedProposals[1:]
	}

	feature := builder.
		Setup(setupSimpleAppWorkload).
		Assess("Send traffic in a namespace without the learning label", sendLearningTraffic).
		Assess("Check no proposal is created", assessNoProposalCreated).
		Assess("Add the learning label to the namespace", setLearningLabel(true)).
		Assess("Send traffic in a namespace with the learning label", sendLearningTraffic).
		Assess("Check proposals are created",
			func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
				return assessProposalsCreated(ctx, t, expectedProposals)
			}).
		Teardown(teardownSimpleAppWorkload).
		Teardown(teardownTestNamespace).
		Feature()

	testEnv.Test(t, feature)
}

func setLearningLabel(enabled bool) features.Func {
	return func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
		t.Helper()
		namespace := getNamespace(ctx)
		r := getSecurityV1Alpha1Client(ctx)

		ns := &corev1.Namespace{Name: namespace}
		require.NoError(t, r.Get(ctx, namespace, "", ns), "failed to get test namespace %q", namespace)
		if enabled {
			if ns.Labels == nil {
				ns.Labels = map[string]string{}
			}
			ns.Labels[learningNamespaceLabelKey] = learningNamespaceLabelValue
		} else {
			delete(ns.Labels, learningNamespaceLabelKey)
		}
		require.NoError(t, r.Update(ctx, ns), "failed to update learning label on namespace %q", namespace)
		return ctx
	}
}

func sendLearningTraffic(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	t.Helper()
	return assertPacketSentFromClient(ctx, t, corev1.ProtocolTCP, simpleAppTCPServicePort)
}

func assessNoProposalCreated(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	t.Helper()
	namespace := getNamespace(ctx)

	require.Never(t, func() bool {
		var proposals securityv1alpha1.WorkloadNetworkPolicyProposalList
		if err := getSecurityV1Alpha1Client(ctx).WithNamespace(namespace).List(ctx, &proposals); err != nil {
			t.Errorf("failed to list proposals in namespace %q: %v", namespace, err)
			return true
		}
		return len(proposals.Items) > 0
	}, proposalIsNotCreatedTimeout, 3*time.Second, "proposal should not be created in namespace %q", namespace)
	return ctx
}

func assessProposalsCreated(ctx context.Context, t *testing.T, names []string) context.Context {
	t.Helper()
	namespace := getNamespace(ctx)

	for _, name := range names {
		require.Eventually(t, func() bool {
			var proposal securityv1alpha1.WorkloadNetworkPolicyProposal
			err := getSecurityV1Alpha1Client(ctx).Get(ctx, name, namespace, &proposal)
			if err != nil {
				t.Logf("proposal %q not available yet: %v", name, err)
			}
			return err == nil
		}, defaultOperationTimeout, 3*time.Second, "proposal %q was not created", name)
	}
	return ctx
}
