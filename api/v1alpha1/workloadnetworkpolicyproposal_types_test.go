package v1alpha1

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestWorkloadNetworkPolicyProposalPromotionLabel(t *testing.T) {
	t.Run("nil proposal", func(t *testing.T) {
		var p *WorkloadNetworkPolicyProposal
		mode, has := p.HasPromotionLabel()
		require.False(t, has)
		require.Empty(t, mode)
		p.SetPromotionLabel(WorkloadNetworkPolicyModeMonitor)
	})

	t.Run("missing label", func(t *testing.T) {
		p := &WorkloadNetworkPolicyProposal{}
		mode, has := p.HasPromotionLabel()
		require.False(t, has)
		require.Empty(t, mode)
	})

	tests := []struct {
		name       string
		labelValue string
		wantHas    bool
		wantMode   WorkloadNetworkPolicyMode
	}{
		{
			name:       "monitor",
			labelValue: string(WorkloadNetworkPolicyModeMonitor),
			wantHas:    true,
			wantMode:   WorkloadNetworkPolicyModeMonitor,
		},
		{
			name:       "protect",
			labelValue: string(WorkloadNetworkPolicyModeProtect),
			wantHas:    true,
			wantMode:   WorkloadNetworkPolicyModeProtect,
		},
		{
			name:       "unsupported value is ignored",
			labelValue: "invalid",
			wantHas:    false,
			wantMode:   "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := &WorkloadNetworkPolicyProposal{
				Labels: map[string]string{
					ProposalPromoteLabelKey: tc.labelValue,
				},
			}
			mode, has := p.HasPromotionLabel()
			require.Equal(t, tc.wantHas, has)
			require.Equal(t, tc.wantMode, mode)
		})
	}

	t.Run("SetPromotionLabel sets mode", func(t *testing.T) {
		p := &WorkloadNetworkPolicyProposal{}
		p.SetPromotionLabel(WorkloadNetworkPolicyModeProtect)
		mode, has := p.HasPromotionLabel()
		require.True(t, has)
		require.Equal(t, string(WorkloadNetworkPolicyModeProtect), p.Labels[ProposalPromoteLabelKey])
		require.Equal(t, WorkloadNetworkPolicyModeProtect, mode)
	})
}
