package scraper

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	networkingv1 "k8s.io/api/networking/v1"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	securityv1alpha1 "github.com/kubewarden/network-enforcer/api/v1alpha1"
	"github.com/kubewarden/network-enforcer/internal/types"
	"github.com/kubewarden/network-enforcer/internal/violation"
	"github.com/kubewarden/network-enforcer/internal/workload"
)

var (
	errUnsupportedProtocol   = errors.New("unsupported protocol")
	errEndpointHasNoWorkload = errors.New("endpoint has no associated workload")
	errSkipWorkload          = errors.New("endpoint has no supported workload")
	errPortOutOfRange        = errors.New("port is out of range")
)

const (
	minValidPort = 1
	maxValidPort = 65535
)

type flowPort interface {
	~int64 | ~uint32
}

// portToInt32 narrows a port reported by a CNI flow API to int32, the range check avoids a gosec suppression.
// A port of 0 is accepted because it is the value the flow APIs report when the port is unavailable.
func portToInt32[T flowPort](port T) (int32, error) {
	if port < 0 || port > maxValidPort {
		return 0, fmt.Errorf("%w: %d", errPortOutOfRange, port)
	}
	return int32(port), nil
}

// parsePort parses a port coming from a string attribute and validates it against the 1 - 65535 range.
func parsePort(port string) (int32, error) {
	parsed, err := strconv.ParseInt(port, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("cannot parse port %q: %w", port, err)
	}
	if parsed < minValidPort || parsed > maxValidPort {
		return 0, fmt.Errorf("%w: %d", errPortOutOfRange, parsed)
	}
	return portToInt32(parsed)
}

type processFlowOutcome int

const (
	processFlowOutcomeSkip processFlowOutcome = iota
	processFlowOutcomeEnqueue
	processFlowOutcomeViolation
	processFlowOutcomeError
)

type processFlowResult struct {
	outcome     processFlowOutcome
	event       types.LearningEvent
	observation violation.Observation
	err         error
}

func processFlowSkip() processFlowResult {
	return processFlowResult{outcome: processFlowOutcomeSkip}
}

func processFlowEnqueue(event types.LearningEvent) processFlowResult {
	return processFlowResult{outcome: processFlowOutcomeEnqueue, event: event}
}

func processFlowRecordViolation(observation violation.Observation) processFlowResult {
	return processFlowResult{outcome: processFlowOutcomeViolation, observation: observation}
}

func processFlowError(err error) processFlowResult {
	return processFlowResult{outcome: processFlowOutcomeError, err: err}
}

func resolveOutcome(role string, err error) processFlowResult {
	if errors.Is(err, errSkipWorkload) {
		return processFlowSkip()
	}
	return processFlowError(fmt.Errorf("cannot resolve %s workload: %w", role, err))
}

func bindResolveDenyingPolicy(
	c client.Client,
) func(context.Context, *securityv1alpha1.WorkloadRef) (k8stypes.NamespacedName, error) {
	return func(ctx context.Context, ref *securityv1alpha1.WorkloadRef) (k8stypes.NamespacedName, error) {
		return workload.ResolveDenyingPolicy(ctx, c, ref)
	}
}

func resolveViolationDenyingPolicy(
	ctx context.Context,
	resolvePolicy func(context.Context, *securityv1alpha1.WorkloadRef) (k8stypes.NamespacedName, error),
	observation *violation.Observation,
) error {
	if observation.DenyingPolicyName != "" {
		// Calico could have already resolved the policy name
		// so we do that only if necessary
		return nil
	}
	// this is the correct workload if the direction is egress
	ref := &observation.Source
	if observation.Direction == networkingv1.PolicyTypeIngress {
		ref = &observation.Dest
	}

	policy, err := resolvePolicy(ctx, ref)
	if err != nil {
		return fmt.Errorf("cannot resolve denying policy: %w", err)
	}

	observation.DenyingPolicyName = policy.Name
	observation.DenyingPolicyNamespace = policy.Namespace
	return nil
}

func resolveParsedFlow(
	ctx context.Context,
	resolveWorkload func(context.Context, *securityv1alpha1.WorkloadRef) error,
	resolvePolicy func(context.Context, *securityv1alpha1.WorkloadRef) (k8stypes.NamespacedName, error),
	parsed processFlowResult,
) processFlowResult {
	var source *securityv1alpha1.WorkloadRef
	var dest *securityv1alpha1.WorkloadRef
	switch parsed.outcome {
	case processFlowOutcomeEnqueue:
		source = parsed.event.Source
		dest = parsed.event.Dest
	case processFlowOutcomeViolation:
		source = &parsed.observation.Source
		dest = &parsed.observation.Dest
	case processFlowOutcomeError, processFlowOutcomeSkip:
		fallthrough
	default:
		return parsed
	}

	if err := resolveWorkload(ctx, source); err != nil {
		return resolveOutcome("source", err)
	}
	if err := resolveWorkload(ctx, dest); err != nil {
		return resolveOutcome("destination", err)
	}

	// in case of learning event there are no other things to do.
	if parsed.outcome == processFlowOutcomeViolation {
		if err := resolveViolationDenyingPolicy(ctx, resolvePolicy, &parsed.observation); err != nil {
			return processFlowError(err)
		}
	}

	return parsed
}

func completeSelector(ctx context.Context, c client.Client, ref *securityv1alpha1.WorkloadRef) error {
	if err := workload.LookupPodSelectorForWorkload(ctx, c, ref); err != nil {
		return fmt.Errorf("failed to lookup pod selector for workload %q: %w", ref.OwnerName, err)
	}
	return nil
}
