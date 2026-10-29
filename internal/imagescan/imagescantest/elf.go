package imagescantest

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
)

const (
	elfHeaderSize  = 64
	progHeaderSize = 56
	dynEntrySize   = 16
	interpPath     = "/lib/ld-test.so\x00"
)

// ELFSpec describes a minimal 64-bit little-endian ELF file. The file has
// only an ELF header, program headers and their data: no sections. This is
// enough for the classification of executables.
type ELFSpec struct {
	Type elf.Type
	// Interp adds a PT_INTERP segment.
	Interp bool
	// Dynamic adds a PT_DYNAMIC segment.
	Dynamic bool
	// Flags1 is the value of DT_FLAGS_1 in the dynamic segment. Zero means
	// no DT_FLAGS_1 entry.
	Flags1 elf.DynFlag1
}

// ELF returns the bytes of a minimal ELF file.
func ELF(spec ELFSpec) []byte {
	var dynamic []elf.Dyn64
	if spec.Dynamic {
		if spec.Flags1 != 0 {
			dynamic = append(dynamic, elf.Dyn64{Tag: int64(elf.DT_FLAGS_1), Val: uint64(spec.Flags1)})
		}
		dynamic = append(dynamic, elf.Dyn64{Tag: int64(elf.DT_NULL)})
	}

	var progs []elf.Prog64
	offset := uint64(elfHeaderSize)
	if spec.Interp {
		progs = append(progs, elf.Prog64{Type: uint32(elf.PT_INTERP)})
	}
	if spec.Dynamic {
		progs = append(progs, elf.Prog64{Type: uint32(elf.PT_DYNAMIC)})
	}
	offset += uint64(len(progs) * progHeaderSize)

	for i := range progs {
		size := uint64(len(interpPath))
		if elf.ProgType(progs[i].Type) == elf.PT_DYNAMIC {
			size = uint64(len(dynamic) * dynEntrySize)
		}
		progs[i].Off = offset
		progs[i].Filesz = size
		progs[i].Memsz = size
		progs[i].Flags = uint32(elf.PF_R)
		offset += size
	}

	header := elf.Header64{
		Type:      uint16(spec.Type),
		Machine:   uint16(elf.EM_X86_64),
		Version:   uint32(elf.EV_CURRENT),
		Phoff:     elfHeaderSize,
		Ehsize:    elfHeaderSize,
		Phentsize: progHeaderSize,
		Phnum:     uint16(len(progs)), //nolint:gosec // at most two program headers.
	}
	copy(header.Ident[:], elf.ELFMAG)
	header.Ident[elf.EI_CLASS] = byte(elf.ELFCLASS64)
	header.Ident[elf.EI_DATA] = byte(elf.ELFDATA2LSB)
	header.Ident[elf.EI_VERSION] = byte(elf.EV_CURRENT)

	var buf bytes.Buffer
	write := func(v any) {
		// Writes to a bytes.Buffer do not fail.
		_ = binary.Write(&buf, binary.LittleEndian, v)
	}
	write(header)
	for _, p := range progs {
		write(p)
	}
	for _, p := range progs {
		if elf.ProgType(p.Type) == elf.PT_INTERP {
			buf.WriteString(interpPath)
			continue
		}
		for _, d := range dynamic {
			write(d)
		}
	}
	return buf.Bytes()
}
