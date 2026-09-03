package bpf

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/kubewarden/runtime-enforcer/internal/types/policymode"
)

type PolicyModeOperation uint8

const (
	_ PolicyModeOperation = iota
	UpdateMode
	DeleteMode
)

func (m *Manager) updatePolicyMode(policyID uint64, mode policymode.Mode) error {
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

func (m *Manager) deletePolicy(policyID uint64) error {
	if err := m.objs.PolicyModeMap.Delete(&policyID); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf(
			"failed to delete policy (id=%d) from map %s: %w",
			policyID,
			m.objs.PolicyModeMap.String(),
			err,
		)
	}
	return nil
}

func (m *Manager) GetPolicyModeUpdateFunc() func(policyID uint64, mode policymode.Mode, op PolicyModeOperation) error {
	return func(policyID uint64, mode policymode.Mode, op PolicyModeOperation) error {
		switch op {
		case UpdateMode:
			return m.handleErrOnShutdown(m.updatePolicyMode(policyID, mode))
		case DeleteMode:
			return m.handleErrOnShutdown(m.deletePolicy(policyID))
		default:
			panic("unhandled policy mode")
		}
	}
}
