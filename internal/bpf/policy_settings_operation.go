package bpf

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"

	"github.com/kubewarden/runtime-enforcer/internal/types/policymode"
)

type PolicySettingsOperation uint8

const (
	_ PolicySettingsOperation = iota
	UpdateSettings
	DeleteSettings
)

func (m *Manager) updatePolicySettings(policyID uint64, mode policymode.Mode, allowForeignRoot bool) error {
	settings := bpfPolicySettings{Mode: uint8(mode)}
	if allowForeignRoot {
		settings.AllowForeignRoot = 1
	}
	if err := m.objs.PolicySettingsMap.Update(&policyID, &settings, ebpf.UpdateAny); err != nil {
		return fmt.Errorf(
			"failed to update policy (id=%d) in map %s with mode %s and allowForeignRootExec=%t: %w",
			policyID,
			m.objs.PolicySettingsMap.String(),
			mode.String(),
			allowForeignRoot,
			err,
		)
	}
	return nil
}

func (m *Manager) deletePolicySettings(policyID uint64) error {
	if err := m.objs.PolicySettingsMap.Delete(&policyID); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf(
			"failed to delete policy (id=%d) from map %s: %w",
			policyID,
			m.objs.PolicySettingsMap.String(),
			err,
		)
	}
	return nil
}

func (m *Manager) GetPolicySettingsUpdateFunc() func(
	policyID uint64,
	mode policymode.Mode,
	allowForeignRoot bool,
	op PolicySettingsOperation,
) error {
	return func(policyID uint64, mode policymode.Mode, allowForeignRoot bool, op PolicySettingsOperation) error {
		switch op {
		case UpdateSettings:
			return m.handleErrOnShutdown(m.updatePolicySettings(policyID, mode, allowForeignRoot))
		case DeleteSettings:
			return m.handleErrOnShutdown(m.deletePolicySettings(policyID))
		default:
			panic("unhandled policy settings operation")
		}
	}
}
