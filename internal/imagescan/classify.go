package imagescan

import (
	"bytes"
	"debug/elf"
	"errors"
	"io"
)

// Kind is the kind of an executable file.
type Kind string

const (
	// KindProgram is an ELF program, dynamically or statically linked.
	KindProgram Kind = "program"
	// KindLibrary is an ELF shared library. A program loads it, but does
	// not run it.
	KindLibrary Kind = "library"
	// KindScript is a file that starts with "#!".
	KindScript Kind = "script"
	// KindUnknown is any other file. The kernel cannot run it, unless a
	// binfmt_misc handler of the node knows the format.
	KindUnknown Kind = "unknown"
)

const (
	elfMagic     = "\x7fELF"
	shebang      = "#!"
	headerLength = len(elfMagic)

	dynEntrySize32 = 8
	dynEntrySize64 = 16
)

// classify returns the kind of the file with the given contents.
//
// An ELF file of type ET_DYN is both the format of a shared library and of a
// position independent program. It is a program when it has a PT_INTERP
// segment, or when its dynamic segment has the DF_1_PIE flag, which the
// linker sets on static-pie programs. Otherwise it is a library. The `file`
// utility uses the same signals.
//
// When in doubt, classify returns KindProgram: dropping a program from a
// policy blocks the workload, keeping a library is only noise.
func classify(r io.Reader) (Kind, error) {
	head := make([]byte, headerLength)
	n, err := io.ReadFull(r, head)
	if err != nil && !isShortRead(err) {
		return "", err
	}
	head = head[:n]

	switch {
	case bytes.HasPrefix(head, []byte(shebang)):
		return KindScript, nil
	case !bytes.Equal(head, []byte(elfMagic)):
		return KindUnknown, nil
	}

	data, err := io.ReadAll(io.MultiReader(bytes.NewReader(head), r))
	if err != nil {
		return "", err
	}
	return classifyELF(data), nil
}

func isShortRead(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
}

func classifyELF(data []byte) Kind {
	f, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		return KindProgram
	}
	defer f.Close()

	// The kernel only runs ET_EXEC and ET_DYN files.
	if f.Type == elf.ET_NONE || f.Type == elf.ET_REL || f.Type == elf.ET_CORE {
		return KindUnknown
	}
	if f.Type == elf.ET_DYN && !hasInterp(f) && !isPIE(f) {
		return KindLibrary
	}
	return KindProgram
}

func hasInterp(f *elf.File) bool {
	for _, p := range f.Progs {
		if p.Type == elf.PT_INTERP {
			return true
		}
	}
	return false
}

// isPIE reports if the DF_1_PIE flag is set in the dynamic segment. It reads
// the PT_DYNAMIC segment, as the kernel does, and not the .dynamic section,
// which a stripped binary can lack. When the segment cannot be read, isPIE
// returns true, so that the file counts as a program.
func isPIE(f *elf.File) bool {
	for _, p := range f.Progs {
		if p.Type != elf.PT_DYNAMIC {
			continue
		}
		data, err := io.ReadAll(p.Open())
		if err != nil {
			return true
		}
		flags, found := dynValue(f, data, elf.DT_FLAGS_1)
		return found && flags&uint64(elf.DF_1_PIE) != 0
	}
	return false
}

// dynValue returns the value of the first entry with the given tag in the
// raw contents of a dynamic segment.
func dynValue(f *elf.File, data []byte, tag elf.DynTag) (uint64, bool) {
	order := f.ByteOrder
	size := dynEntrySize64
	if f.Class == elf.ELFCLASS32 {
		size = dynEntrySize32
	}

	for len(data) >= size {
		var t elf.DynTag
		var v uint64
		if f.Class == elf.ELFCLASS32 {
			t = elf.DynTag(int32(order.Uint32(data[0:4]))) //nolint:gosec // the tag is a signed 32-bit value.
			v = uint64(order.Uint32(data[4:8]))
		} else {
			t = elf.DynTag(int64(order.Uint64(data[0:8]))) //nolint:gosec // the tag is a signed 64-bit value.
			v = order.Uint64(data[8:16])
		}
		if t == elf.DT_NULL {
			return 0, false
		}
		if t == tag {
			return v, true
		}
		data = data[size:]
	}
	return 0, false
}
