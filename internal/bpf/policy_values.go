package bpf

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/neuvector/runtime-enforcer/internal/kernels"
)

type PolicyValuesOperation int

const (
	_ PolicyValuesOperation = iota
	AddValuesToPolicy
	RemoveValuesFromPolicy
	ReplaceValuesInPolicy
)

const (
	StringMapsNumSubMapsSmall = 8
	StringMapsNumSubMaps      = 11
	MaxStringMapsSize         = 4096
	stringMapsKeyIncSize      = 24

	stringMapSize0  = 1 * stringMapsKeyIncSize
	stringMapSize1  = 2 * stringMapsKeyIncSize
	stringMapSize2  = 3 * stringMapsKeyIncSize
	stringMapSize3  = 4 * stringMapsKeyIncSize
	stringMapSize4  = 5 * stringMapsKeyIncSize
	stringMapSize5  = 6 * stringMapsKeyIncSize
	stringMapSize6  = 256
	stringMapSize7  = 512
	stringMapSize8  = 1024
	stringMapSize9  = 2048
	stringMapSize10 = 4096

	// For kernels before 5.9 we need to fix the max entries for inner maps, the chosen value is arbitrary.
	fixedMaxEntriesPre5_9 = 500
)

const (
	// BPFFNoPrealloc is the flag for BPF_MAP_CREATE that disables preallocation. Must match values from linux/bpf.h.
	BPFFNoPrealloc = 1 << 0
)

//nolint:gochecknoglobals // stringMapsSizes is effectively const
var stringMapsSizes = [StringMapsNumSubMaps]int{
	stringMapSize0,
	stringMapSize1,
	stringMapSize2,
	stringMapSize3,
	stringMapSize4,
	stringMapSize5,
	stringMapSize6,
	stringMapSize7,
	stringMapSize8,
	stringMapSize9,
	stringMapSize10,
}

type SelectorStringMaps [StringMapsNumSubMaps]map[[MaxStringMapsSize]byte]struct{}

func createStringMaps() SelectorStringMaps {
	return SelectorStringMaps{
		{},
		{},
		{},
		{},
		{},
		{},
		{},
		{},
		{},
		{},
		{},
	}
}

func stringPaddedLen(s int) int {
	paddedLen := s

	if s <= 6*stringMapsKeyIncSize {
		if s%stringMapsKeyIncSize != 0 {
			paddedLen = ((s / stringMapsKeyIncSize) + 1) * stringMapsKeyIncSize
		}
		return paddedLen
	}
	if s <= stringMapSize6 {
		return stringMapSize6
	}
	if s <= stringMapSize7 {
		return stringMapSize7
	}
	if s <= stringMapSize8 {
		return stringMapSize8
	}
	if s <= stringMapSize9 {
		return stringMapSize9
	}
	return stringMapSize10
}

func argStringSelectorValue(v string, removeNul bool, currKernelVer int) ([MaxStringMapsSize]byte, int, error) {
	if removeNul {
		// Remove any trailing nul characters ("\0" or 0x00)
		for v[len(v)-1] == 0 {
			v = v[0 : len(v)-1]
		}
	}
	ret := [MaxStringMapsSize]byte{}
	b := []byte(v)
	s := len(b)

	if s == 0 {
		return ret, 0, errors.New("string is empty")
	}

	switch {
	case kernels.VersionIsLowerThan(currKernelVer, "5.11"):
		// Until 5.11 we have max size of 512
		if s > stringMapSize7 {
			return ret, 0, errors.New("string is too long")
		}
	default:
		if s > MaxStringMapsSize {
			return ret, 0, errors.New("string is too long")
		}
	}
	// Calculate length of string padded to next multiple of key increment size
	paddedLen := stringPaddedLen(s)

	copy(ret[:], b)
	return ret, paddedLen, nil
}

func putValueInMap(m SelectorStringMaps, v string) error {
	value, size, err := argStringSelectorValue(v, false, kernels.GetCurrKernelVersion())
	if err != nil {
		return fmt.Errorf("value %s invalid: %w", v, err)
	}

	// Here we are sure the size matches one of the supported map sizes for the current kernel version
	for sizeIdx := range StringMapsNumSubMaps {
		if size == stringMapsSizes[sizeIdx] {
			m[sizeIdx][value] = struct{}{}
			return nil
		}
	}
	// if we arrive here it means that no map was found for the given size this is an error
	return fmt.Errorf("value %s has unsupported padded size %d", v, size)
}

func convertValuesToBPFStringMaps(values []string) (SelectorStringMaps, error) {
	maps := createStringMaps()
	for _, v := range values {
		if err := putValueInMap(maps, v); err != nil {
			return maps, err
		}
	}
	return maps, nil
}

func (m *Manager) cleanupPinnedMaps(name string, innerMap *ebpf.Map) {
	if m.pinPath != "" {
		pinFile := filepath.Join(m.pinPath, name)
		// Remove pin file first (like in removeBPFMaps)
		if err := os.Remove(pinFile); err != nil && !os.IsNotExist(err) {
			m.logger.Error("failed to remove pin file", "name", name, "path", pinFile, "error", err)
		} else if err == nil {
			m.logger.Debug("cleaned up inner map after error", "name", name, "path", pinFile)
		}
	}
	// Close the map after unpinning
	err := innerMap.Close()
	if err != nil {
		m.logger.Error("failed to close inner map", "name", name)
	}
}

func (m *Manager) generateInnerBPFMaps(policyID uint64,
	index int, isPre5_9 bool, subMap map[[MaxStringMapsSize]byte]struct{}) error {
	mapKeySize := stringMapsSizes[index]
	name := fmt.Sprintf("p_%d_str_map_%d", policyID, index)
	innerSpec := &ebpf.MapSpec{
		Name:       name,
		Type:       ebpf.Hash,
		KeySize:    uint32(mapKeySize), //nolint:gosec // mapKeySize cannot be larger than math.MaxUint32
		ValueSize:  uint32(1),
		MaxEntries: uint32(len(subMap)), //nolint:gosec // len(...) cannot be larger than math.MaxUint32
	}

	// Versions before 5.9 do not allow inner maps to have different sizes.
	// See: https://lore.kernel.org/bpf/20200828011800.1970018-1-kafai@fb.com/
	if isPre5_9 {
		innerSpec.Flags = uint32(BPFFNoPrealloc)
		innerSpec.MaxEntries = uint32(fixedMaxEntriesPre5_9)
	}

	inner, err := ebpf.NewMap(innerSpec)
	if err != nil {
		return fmt.Errorf("failed to create inner_map: %w", err)
	}

	// Pin the inner map if pinPath is configured
	if m.pinPath != "" {
		pinFile := filepath.Join(m.pinPath, name)
		if err = inner.Pin(pinFile); err != nil {
			_ = inner.Close()
			return fmt.Errorf("failed to pin inner map %s: %w", name, err)
		}
		m.logger.Debug("pinned inner map", "name", name, "path", pinFile)
	}

	// Ensure cleanup on error
	cleanupOnError := true
	defer func() {
		if cleanupOnError {
			m.cleanupPinnedMaps(name, inner)
		}
	}()

	// update values
	// todo: ideally we should rollback if any of these fail
	one := uint8(1)
	for rawVal := range subMap {
		val := rawVal[:mapKeySize]
		err = inner.Update(val, one, 0)
		if err != nil {
			return fmt.Errorf("failed to insert value into %s: %w", name, err)
		}
	}

	err = m.policyStringMaps[index].Update(policyID, inner, ebpf.UpdateNoExist)
	if err != nil && errors.Is(err, ebpf.ErrKeyExist) {
		m.logger.Warn("inner policy map entry already exists, retrying update", "map", name, "policyID", policyID)
		err = m.policyStringMaps[index].Update(policyID, inner, 0)
	}
	if err != nil {
		return fmt.Errorf("failed to insert inner policy (id=%d) map: %w", policyID, err)
	}

	// Success, don't cleanup
	cleanupOnError = false
	m.logger.Info("handler: add new inner map inside policy str", "name", name)

	// Close the map handle but leave it pinned
	err = inner.Close()
	if err != nil {
		return fmt.Errorf("failed to close inner map: %w", err)
	}
	return nil
}

func (m *Manager) generateBPFMaps(policyID uint64, values []string) error {
	subMaps, err := convertValuesToBPFStringMaps(values)
	if err != nil {
		return err
	}

	isPre5_9 := m.isKernelPre5_9()
	for i := range subMaps {
		// if the subMap is empty we skip it
		if len(subMaps[i]) == 0 {
			continue
		}

		if err = m.generateInnerBPFMaps(policyID, i, isPre5_9, subMaps[i]); err != nil {
			return err
		}
	}
	return nil
}

func (m *Manager) removeBPFMaps(policyID uint64) error {
	// Unpin inner maps if pinning is enabled
	if m.pinPath != "" {
		for i := range StringMapsNumSubMaps {
			name := fmt.Sprintf("p_%d_str_map_%d", policyID, i)
			pinFile := filepath.Join(m.pinPath, name)
			// Try to unpin - ignore errors if the file doesn't exist
			if err := os.Remove(pinFile); err != nil && !os.IsNotExist(err) {
				m.logger.Warn("failed to unpin inner map", "name", name, "path", pinFile, "error", err)
			} else if err == nil {
				m.logger.Debug("unpinned inner map", "name", name, "path", pinFile)
			}
		}
	}

	for _, policyMap := range m.policyStringMaps {
		if err := policyMap.Delete(policyID); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("failed to remove policy (id=%d) from map %s: %w", policyID, policyMap.String(), err)
		}
	}
	return nil
}

func (m *Manager) replaceBPFMaps(policyID uint64, values []string) error {
	subMaps, err := convertValuesToBPFStringMaps(values)
	if err != nil {
		return err
	}

	isPre5_9 := m.isKernelPre5_9()
	for i := range subMaps {
		if len(subMaps[i]) == 0 {
			// No values for this size bucket - delete the old inner map if it exists
			if err = m.policyStringMaps[i].Delete(policyID); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
				return fmt.Errorf("failed to remove policy (id=%d) from map %s: %w",
					policyID, m.policyStringMaps[i].String(), err)
			}
			continue
		}

		// Create and populate new inner map, then atomically replace
		if err = m.replaceInnerBPFMap(policyID, i, isPre5_9, subMaps[i]); err != nil {
			return err
		}
	}
	return nil
}

func (m *Manager) replaceInnerBPFMap(policyID uint64,
	index int, isPre5_9 bool, subMap map[[MaxStringMapsSize]byte]struct{}) error {
	mapKeySize := stringMapsSizes[index]
	name := fmt.Sprintf("p_%d_str_map_%d", policyID, index)
	innerSpec := &ebpf.MapSpec{
		Name:       name,
		Type:       ebpf.Hash,
		KeySize:    uint32(mapKeySize), //nolint:gosec // mapKeySize cannot be larger than math.MaxUint32
		ValueSize:  uint32(1),
		MaxEntries: uint32(len(subMap)), //nolint:gosec // len(...) cannot be larger than math.MaxUint32
	}

	if isPre5_9 {
		innerSpec.Flags = uint32(BPFFNoPrealloc)
		innerSpec.MaxEntries = uint32(fixedMaxEntriesPre5_9)
	}

	inner, err := ebpf.NewMap(innerSpec)
	if err != nil {
		return fmt.Errorf("failed to create inner_map: %w", err)
	}
	defer inner.Close()

	one := uint8(1)
	for rawVal := range subMap {
		val := rawVal[:mapKeySize]
		err = inner.Update(val, one, 0)
		if err != nil {
			return fmt.Errorf("failed to insert value into %s: %w", name, err)
		}
	}

	// Use UpdateExist to atomically replace the old inner map
	err = m.policyStringMaps[index].Update(policyID, inner, ebpf.UpdateExist)
	if err != nil {
		return fmt.Errorf("failed to replace inner policy (id=%d) map: %w", policyID, err)
	}
	m.logger.Info("handler: replaced inner map inside policy str", "name", name)
	return nil
}

// GetPolicyValuesUpdateFunc exposes a function used to interact with BPF maps storing policy values.
func (m *Manager) GetPolicyValuesUpdateFunc() func(policyID uint64, values []string, op PolicyValuesOperation) error {
	return func(policyID uint64, values []string, op PolicyValuesOperation) error {
		switch op {
		case AddValuesToPolicy:
			return m.generateBPFMaps(policyID, values)
		case RemoveValuesFromPolicy:
			return m.removeBPFMaps(policyID)
		case ReplaceValuesInPolicy:
			return m.replaceBPFMaps(policyID, values)
		default:
			panic("unhandled operation")
		}
	}
}
