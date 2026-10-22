package v1alpha1

import (
	"sort"
	"strings"
)

// OptionAllowForeignRootExec is the options key that lets a container run
// binaries on a foreign root file system. See WorkloadPolicyRules.Options.
const OptionAllowForeignRootExec = "ALLOW_FOREIGN_ROOT_EXEC"

// isKnownOption reports whether the enforcer recognizes an options key. The
// enforcer ignores keys that it does not recognize.
func isKnownOption(key string) bool {
	switch key {
	case OptionAllowForeignRootExec:
		return true
	default:
		return false
	}
}

// optionEnabled reports whether an options value turns a behavior on. A value of
// "1" or "true" (case-insensitive, after trimming spaces) turns the behavior on.
// Any other value, including an empty string, leaves it off. A typed-wrong value
// fails closed.
func optionEnabled(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true":
		return true
	default:
		return false
	}
}

// AllowForeignRootExec reports whether the container opts out of foreign-root
// denial. It reads the OptionAllowForeignRootExec key from the options map.
func (r *WorkloadPolicyRules) AllowForeignRootExec() bool {
	return optionEnabled(r.Options[OptionAllowForeignRootExec])
}

// UnknownOptionKeys returns the options keys that the enforcer does not
// recognize. The result is sorted. The caller uses it to warn about stale or
// mistyped keys.
func UnknownOptionKeys(options map[string]string) []string {
	var unknown []string
	for key := range options {
		if !isKnownOption(key) {
			unknown = append(unknown, key)
		}
	}
	sort.Strings(unknown)
	return unknown
}
