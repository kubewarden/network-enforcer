package e2e_test

import (
	"context"
	"fmt"

	"sigs.k8s.io/e2e-framework/pkg/env"
	"sigs.k8s.io/e2e-framework/pkg/envconf"

	netypes "github.com/kubewarden/network-enforcer/internal/types"
)

// installProvider sets up the data-plane provider selected via
// E2E_PROVIDER.
func installProvider() env.Func {
	return func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		switch getSuiteConfig(ctx).ProviderName() {
		case string(netypes.ProviderIstio):
			return installIstioMesh()(ctx, cfg)
		case string(netypes.ProviderCilium):
			return installCilium(ctx, cfg)
		case string(netypes.ProviderCalico):
			return installCalico(ctx, cfg)
		default:
			return ctx, fmt.Errorf("unsupported provider: %q", getSuiteConfig(ctx).ProviderName())
		}
	}
}
