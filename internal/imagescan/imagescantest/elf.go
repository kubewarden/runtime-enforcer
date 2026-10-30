package imagescantest

import (
	"bytes"
	"cmp"
	"debug/elf"
	"encoding/binary"
)

const interpPath = "/lib/ld-test.so\x00"

// ELFSpec describes a minimal ELF file. The file has only an ELF header,
// program headers and their data: no sections. This is enough for the
// classification of executables.
type ELFSpec struct {
	Type elf.Type
	// Class is ELFCLASS32 or ELFCLASS64. Zero means ELFCLASS64.
	Class elf.Class
	// Data is the byte order, ELFDATA2LSB or ELFDATA2MSB. Zero means
	// ELFDATA2LSB.
	Data elf.Data
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
	is32 := cmp.Or(spec.Class, elf.ELFCLASS64) == elf.ELFCLASS32
	var order binary.ByteOrder = binary.LittleEndian
	if spec.Data == elf.ELFDATA2MSB {
		order = binary.BigEndian
	}

	headerSize, progSize, dynSize := binary.Size(elf.Header64{}), binary.Size(elf.Prog64{}), binary.Size(elf.Dyn64{})
	if is32 {
		headerSize, progSize, dynSize = binary.Size(elf.Header32{}), binary.Size(elf.Prog32{}), binary.Size(elf.Dyn32{})
	}

	// The values are built for ELFCLASS64, and narrowed for ELFCLASS32 when
	// they are written.
	var dynamic []elf.Dyn64
	if spec.Dynamic {
		if spec.Flags1 != 0 {
			dynamic = append(dynamic, elf.Dyn64{Tag: int64(elf.DT_FLAGS_1), Val: uint64(spec.Flags1)})
		}
		dynamic = append(dynamic, elf.Dyn64{Tag: int64(elf.DT_NULL)})
	}

	var progs []elf.Prog64
	if spec.Interp {
		progs = append(progs, elf.Prog64{Type: uint32(elf.PT_INTERP)})
	}
	if spec.Dynamic {
		progs = append(progs, elf.Prog64{Type: uint32(elf.PT_DYNAMIC)})
	}

	offset := uint64(headerSize + len(progs)*progSize) //nolint:gosec // small positive sizes.
	for i := range progs {
		size := uint64(len(interpPath))
		if elf.ProgType(progs[i].Type) == elf.PT_DYNAMIC {
			size = uint64(len(dynamic) * dynSize) //nolint:gosec // small positive sizes.
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
		Phoff:     uint64(headerSize), //nolint:gosec // small positive size.
		Ehsize:    uint16(headerSize), //nolint:gosec // small positive size.
		Phentsize: uint16(progSize),   //nolint:gosec // small positive size.
		Phnum:     uint16(len(progs)), //nolint:gosec // at most two program headers.
	}
	copy(header.Ident[:], elf.ELFMAG)
	header.Ident[elf.EI_CLASS] = byte(cmp.Or(spec.Class, elf.ELFCLASS64))
	header.Ident[elf.EI_DATA] = byte(cmp.Or(spec.Data, elf.ELFDATA2LSB))
	header.Ident[elf.EI_VERSION] = byte(elf.EV_CURRENT)

	var buf bytes.Buffer
	write := func(v64, v32 any) {
		v := v64
		if is32 {
			v = v32
		}
		// Writes to a bytes.Buffer do not fail.
		_ = binary.Write(&buf, order, v)
	}
	write(header, header32(header))
	for _, p := range progs {
		write(p, prog32(p))
	}
	for _, p := range progs {
		if elf.ProgType(p.Type) == elf.PT_INTERP {
			buf.WriteString(interpPath)
			continue
		}
		for _, d := range dynamic {
			write(d, elf.Dyn32{Tag: int32(d.Tag), Val: uint32(d.Val)}) //nolint:gosec // small test values.
		}
	}
	return buf.Bytes()
}

//nolint:gosec // the values of the test files fit in 32 bits.
func header32(h elf.Header64) elf.Header32 {
	return elf.Header32{
		Ident:     h.Ident,
		Type:      h.Type,
		Machine:   h.Machine,
		Version:   h.Version,
		Phoff:     uint32(h.Phoff),
		Ehsize:    h.Ehsize,
		Phentsize: h.Phentsize,
		Phnum:     h.Phnum,
	}
}

//nolint:gosec // the values of the test files fit in 32 bits.
func prog32(p elf.Prog64) elf.Prog32 {
	return elf.Prog32{
		Type:   p.Type,
		Flags:  p.Flags,
		Off:    uint32(p.Off),
		Filesz: uint32(p.Filesz),
		Memsz:  uint32(p.Memsz),
	}
}
