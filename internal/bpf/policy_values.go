package bpf

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/neuvector/runtime-enforcer/internal/kernels"
)

type PolicyValuesOperation int

const (
	_ PolicyValuesOperation = iota
	AddValuesToPolicy
	RemoveValuesFromPolicy
)

const (
	StringMapsNumSubMapsSmall = 8
	StringMapsNumSubMaps      = 11
	MaxStringMapsSize         = 4096 + 2
	stringMapsKeyIncSize      = 24

	// Maps with key string length <256 only require a single byte
	// to store string length. Maps with key string length >=256
	// require two bytes to store string length.
	stringMapSize0  = 1*stringMapsKeyIncSize + 1
	stringMapSize1  = 2*stringMapsKeyIncSize + 1
	stringMapSize2  = 3*stringMapsKeyIncSize + 1
	stringMapSize3  = 4*stringMapsKeyIncSize + 1
	stringMapSize4  = 5*stringMapsKeyIncSize + 1
	stringMapSize5  = 6*stringMapsKeyIncSize + 1
	stringMapSize6  = 256 + 2
	stringMapSize7  = 512 + 2
	stringMapSize8  = 1024 + 2
	stringMapSize9  = 2048 + 2
	stringMapSize10 = 4096 + 2

	StringMapSize7a = 512

	// For kernels before 5.9 we need to fix the max entries for inner maps, the chosen value is arbitrary
	fixedMaxEntriesPre5_9 = 500
)

const (
	// Flags for BPF_MAP_CREATE. Must match values from linux/bpf.h
	BPF_F_NO_PREALLOC = 1 << 0
)

var (
	StringMapsSizes = [StringMapsNumSubMaps]int{
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
)

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
	// The '-2' is to reduce the key size to the key string size -
	// the key includes a string length that is 2 bytes long.
	if s <= stringMapSize6-2 {
		return stringMapSize6 - 2
	}
	if kernels.MinKernelVersion("5.11") {
		if s <= stringMapSize7-2 {
			return stringMapSize7 - 2
		}
		if s <= stringMapSize8-2 {
			return stringMapSize8 - 2
		}
		if s <= stringMapSize9-2 {
			return stringMapSize9 - 2
		}
		return stringMapSize10 - 2
	}
	return StringMapSize7a - 2
}

func argStringSelectorValue(v string, removeNul bool) ([MaxStringMapsSize]byte, int, error) {
	if removeNul {
		// Remove any trailing nul characters ("\0" or 0x00)
		for v[len(v)-1] == 0 {
			v = v[0 : len(v)-1]
		}
	}
	ret := [MaxStringMapsSize]byte{}
	b := []byte(v)
	s := len(b)
	if kernels.MinKernelVersion("5.11") {
		if s > MaxStringMapsSize-2 {
			return ret, 0, errors.New("string is too long")
		}
	} else if kernels.MinKernelVersion("5.4") {
		if s > StringMapSize7a-2 {
			return ret, 0, errors.New("string is too long")
		}
	} else {
		if s > stringMapSize5-1 {
			return ret, 0, errors.New("string is too long")
		}
	}
	if s == 0 {
		return ret, 0, errors.New("string is empty")
	}
	// Calculate length of string padded to next multiple of key increment size
	paddedLen := stringPaddedLen(s)

	// Add real length to start and padding to end.
	// u8 for first 6 maps and u16 little endian for latter maps.
	if paddedLen <= 6*stringMapsKeyIncSize {
		ret[0] = byte(s)
		copy(ret[1:], b)
		// Total length is padded string len + prefixed length byte.
		return ret, paddedLen + 1, nil
	}
	ret[0] = byte(s % 0x100)
	ret[1] = byte(s / 0x100)
	copy(ret[2:], b)
	// Total length is padded string len + prefixed length half word.
	return ret, paddedLen + 2, nil
}

func convertValuesToMaps(values []string) (SelectorStringMaps, error) {
	maps := createStringMaps()
	for _, v := range values {
		// todo!: we use `linux_binprm` so according to tetragon we shouldn't remove the nul, double check
		value, size, err := argStringSelectorValue(v, false)
		if err != nil {
			return maps, fmt.Errorf("value %s invalid: %w", v, err)
		}
		numSubMaps := StringMapsNumSubMaps
		if !kernels.MinKernelVersion("5.11") {
			numSubMaps = StringMapsNumSubMapsSmall
		}

		for sizeIdx := range numSubMaps {
			stringMapSize := StringMapsSizes[sizeIdx]
			if sizeIdx == 7 && !kernels.MinKernelVersion("5.11") {
				stringMapSize = StringMapSize7a
			}

			if size == stringMapSize {
				maps[sizeIdx][value] = struct{}{}
				break
			}
		}
	}
	return maps, nil
}

func (m *Manager) generateBPFMaps(policyID uint64, values []string) error {
	subMaps, err := convertValuesToMaps(values)
	if err != nil {
		return err
	}

	preKernelVersion5_9 := !kernels.MinKernelVersion("5.9")
	preKernelVersion5_11 := !kernels.MinKernelVersion("5.11")

	for i := range subMaps {
		// if the subMap is empty we skip it
		if len(subMaps[i]) == 0 {
			continue
		}

		mapKeySize := StringMapsSizes[i]
		if i == 7 && preKernelVersion5_11 {
			mapKeySize = StringMapSize7a
		}

		name := fmt.Sprintf("p_%d_str_map_%d", policyID, i)
		innerSpec := &ebpf.MapSpec{
			Name:       name,
			Type:       ebpf.Hash,
			KeySize:    uint32(mapKeySize),
			ValueSize:  uint32(1),
			MaxEntries: uint32(len(subMaps[i])),
		}

		// Versions before 5.9 do not allow inner maps to have different sizes.
		// See: https://lore.kernel.org/bpf/20200828011800.1970018-1-kafai@fb.com/
		if preKernelVersion5_9 {
			innerSpec.Flags = uint32(BPF_F_NO_PREALLOC)
			innerSpec.MaxEntries = uint32(fixedMaxEntriesPre5_9)
		}

		inner, err := ebpf.NewMap(innerSpec)
		if err != nil {
			return fmt.Errorf("failed to create inner_map: %w", err)
		}

		// update values
		// todo: ideally we should rollback if any of these fail
		one := uint8(1)
		for rawVal := range subMaps[i] {
			val := rawVal[:mapKeySize]
			err := inner.Update(val, one, 0)
			if err != nil {
				return fmt.Errorf("failed to insert value into %s: %w", name, err)
			}
		}

		err = m.policyStringMaps[i].Update(policyID, uint32(inner.FD()), ebpf.UpdateNoExist)
		if err != nil && errors.Is(err, ebpf.ErrKeyExist) {
			m.logger.Warn("inner policy map entry already exists, retrying update", "map", name, "policyID", policyID)
			err = m.policyStringMaps[i].Update(policyID, uint32(inner.FD()), 0)
		}
		inner.Close()
		if err != nil {
			return fmt.Errorf("failed to insert inner policy (id=%d) map: %w", policyID, err)
		}
		m.logger.Info("handler: add new inner map inside policy str", "name", name)
	}
	return nil
}

func (m *Manager) removeBPFMaps(policyID uint64) error {
	for _, policyMap := range m.policyStringMaps {
		if err := policyMap.Delete(policyID); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("failed to remove policy (id=%d) from map %s: %w", policyID, policyMap.String(), err)
		}
	}
	return nil
}

// Expose some methods to interact with BPF maps
func (m *Manager) GetPolicyValuesUpdateFunc() func(policyID uint64, values []string, op PolicyValuesOperation) error {
	return func(policyID uint64, values []string, op PolicyValuesOperation) error {
		switch op {
		case AddValuesToPolicy:
			return m.generateBPFMaps(policyID, values)
		case RemoveValuesFromPolicy:
			return m.removeBPFMaps(policyID)
		default:
			panic("unhandled operation")
		}
	}
}
