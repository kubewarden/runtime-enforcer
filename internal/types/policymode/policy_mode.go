package policymode

import agentv1 "github.com/kubewarden/runtime-enforcer/proto/agent/v1"

const (
	MonitorString = "monitor"
	ProtectString = "protect"
)

type Mode uint8

const (
	_ Mode = iota
	Monitor
	Protect
)

func (pm Mode) String() string {
	switch pm {
	case Monitor:
		return MonitorString
	case Protect:
		return ProtectString
	default:
		panic("unknown policy mode")
	}
}

func FromUint8(v uint8) Mode {
	switch Mode(v) {
	case Monitor, Protect:
		return Mode(v)
	default:
		panic("unknown uint8 value for policy mode")
	}
}

func IsValid(mode string) bool {
	switch mode {
	case MonitorString, ProtectString:
		return true
	default:
		return false
	}
}

func ParseMode(s string) Mode {
	switch s {
	case MonitorString:
		return Monitor
	case ProtectString:
		return Protect
	default:
		panic("unknown string value for policy mode")
	}
}

func ParsePolicyModeToProto(s string) agentv1.PolicyMode {
	switch s {
	case MonitorString:
		return agentv1.PolicyMode_POLICY_MODE_MONITOR
	case ProtectString:
		return agentv1.PolicyMode_POLICY_MODE_PROTECT
	default:
		return agentv1.PolicyMode_POLICY_MODE_UNSPECIFIED
	}
}
