package bpf

import (
	"fmt"

	"github.com/cilium/ebpf"
)

type PolicyMode uint8

const (
	_ PolicyMode = iota
	Monitor
	Protect
)

func (pm PolicyMode) String() string {
	switch pm {
	case Monitor:
		return "Monitor"
	case Protect:
		return "Protect"
	default:
		panic("unhandled policy mode")
	}
}

func (m *Manager) updatePolicyMode(policyID uint64, mode PolicyMode) error {
	if err := m.objs.PolicyModeMap.Update(&policyID, uint8(mode), ebpf.UpdateAny); err != nil {
		return fmt.Errorf(
			"failed to update policy (id=%d) in map %s with mode %s: %w",
			policyID,
			m.objs.PolicyModeMap.String(),
			mode.String(),
			err,
		)
	}
	return nil
}

func (m *Manager) GetPolicyModeUpdateFunc() func(policyID uint64, op PolicyMode) error {
	return func(policyID uint64, op PolicyMode) error {
		return m.updatePolicyMode(policyID, op)
	}
}
