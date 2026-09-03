package controller

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"

	networkingv1 "k8s.io/api/networking/v1"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	securityv1alpha1 "github.com/kubewarden/network-enforcer/api/v1alpha1"
	"github.com/kubewarden/network-enforcer/internal/types"
)

func (r *LearningReconciler) updateProposal(
	ctx context.Context,
	evt types.LearningEvent,
) error {
	// Istio Ambient L4 authorization is enforced on the receiving side,
	// so learning always targets the ingress proposal.
	proposal := getProposalMetadata(evt.Dest, networkingv1.PolicyTypeIngress)
	if _, err := controllerutil.CreateOrUpdate(ctx, r.Client, proposal, func() error {
		// Populate the Istio backend only when creating the resource the first time.
		if proposal.Spec.Istio == nil {
			proposal.Spec.Backend = securityv1alpha1.PolicyBackendIstio
			proposal.Spec.Istio = &securityv1alpha1.IstioAuthorizationPolicySpec{
				Selector: evt.Dest.Selector,
			}
		}

		upsertIstioLearnedRule(proposal.Spec.Istio, evt.Source.Identity, strconv.FormatInt(int64(evt.DstPort), 10))
		return nil
	}); err != nil {
		return fmt.Errorf("create or update proposal %s/%s: %w", proposal.Namespace, proposal.Name, err)
	}
	return nil
}

// upsertIstioLearnedRule merges a learned (principal, port) into the Istio ruleset.
// Learning only updates rules that target exactly one source principal (a single
// From with a single principal). In Istio, every From/principal in a rule shares
// the same To ports, so adding a port to a multi-source rule would also allow
// that port for the other principals. When no such single-principal rule exists,
// a new rule is appended.
func upsertIstioLearnedRule(
	spec *securityv1alpha1.IstioAuthorizationPolicySpec,
	principal, port string,
) {
	for i := range spec.Rules {
		rule := &spec.Rules[i]
		if len(rule.From) != 1 {
			continue
		}
		principals := rule.From[0].Source.Principals
		if len(principals) != 1 || principals[0] != principal {
			continue
		}
		if len(rule.To) == 0 {
			rule.To = []securityv1alpha1.IstioTo{
				{Operation: securityv1alpha1.IstioOperation{Ports: []string{port}}},
			}
			return
		}
		for _, to := range rule.To {
			if slices.Contains(to.Operation.Ports, port) {
				return
			}
		}
		// Port is new, attach it to the first To entry.
		rule.To[0].Operation.Ports = append(rule.To[0].Operation.Ports, port)
		return
	}

	spec.Rules = append(spec.Rules, securityv1alpha1.IstioAuthorizationPolicyRule{
		From: []securityv1alpha1.IstioFrom{
			{Source: securityv1alpha1.IstioSource{Principals: []string{principal}}},
		},
		To: []securityv1alpha1.IstioTo{
			{Operation: securityv1alpha1.IstioOperation{Ports: []string{port}}},
		},
	})
}

func (r *LearningReconciler) processIstioLearningEvent(ctx context.Context, req types.LearningEvent) error {
	// For istio proposals are inbound, so we always need to create an inbound proposal for
	// the destination.
	if req.Dest == nil {
		return errors.New("invalid learning event: missing destination")
	}
	wk := req.Dest
	proposalName := getProposalName(wk, networkingv1.PolicyTypeIngress)
	policies, err := checkExistingPolicy(ctx, r.Client, wk.Namespace, proposalName)
	if err != nil {
		return fmt.Errorf("checking existing policies for %s/%s: %w", wk.Namespace, proposalName, err)
	}

	switch len(policies) {
	case 0:
		// no policy associated with the proposal
		return r.updateProposal(ctx, req)
	case 1:
		// we do nothing, we already have a policy
		return nil
	default:
		return errors.New("multiple policies associated with the same proposal")
	}
}
