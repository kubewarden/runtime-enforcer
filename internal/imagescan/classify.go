package imagescan

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"io"
	"slices"

	"github.com/kubewarden/runtime-enforcer/internal/elfutil"
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
	shebang = "#!"

	// maxDynamicSize is the largest dynamic segment that classify reads, in
	// bytes. Real dynamic segments are smaller than 2 KiB.
	maxDynamicSize = 64 << 10
)

// errMalformed is returned for a dynamic segment that classify cannot read
// within its limits, or that is not valid. classify counts such a file as a
// program.
var errMalformed = errors.New("malformed ELF dynamic segment")

// classify returns the kind of the file with the given contents. r must be
// at the start of the file.
//
// An ELF file of type ET_DYN is both the format of a shared library and of a
// position independent program. classify counts it as a program when it has
// a PT_INTERP segment, or when its dynamic segment has the DF_1_PIE flag,
// which the linker sets on static-pie programs. Otherwise it is a library.
// This is a heuristic of wpgen. The `file` utility uses similar signals, but
// its answer can be different, for example for glibc's libc.so.6.
//
// classify parses ELF files with debug/elf, through elfutil. elfutil is
// copied from syft, and it rejects the compressed sections that would make
// debug/elf allocate a large amount of memory. classify needs random access
// to parse an ELF file: when r is not an [io.ReaderAt], the file is a program.
//
// When in doubt, classify returns KindProgram: dropping a program from a
// policy blocks the workload, keeping a library is only noise.
func classify(r io.Reader) (Kind, error) {
	head := make([]byte, len(elf.ELFMAG))
	n, err := io.ReadFull(r, head)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return "", err
	}
	head = head[:n]

	switch {
	case bytes.HasPrefix(head, []byte(shebang)):
		return KindScript, nil
	case !bytes.Equal(head, []byte(elf.ELFMAG)):
		return KindUnknown, nil
	}

	ra, ok := r.(io.ReaderAt)
	if !ok {
		return KindProgram, nil
	}
	return classifyELF(ra), nil
}

// classifyELF uses a named result, so that it can return KindProgram when
// debug/elf panics.
//
//nolint:nonamedreturns // recover can only change a named result.
func classifyELF(r io.ReaderAt) (kind Kind) {
	// debug/elf is not hardened against hostile files, and it can panic.
	defer func() {
		if recover() != nil {
			kind = KindProgram
		}
	}()

	f, err := elfutil.NewFile(r)
	if err != nil {
		return KindProgram
	}
	defer f.Close()

	// The kernel only runs ET_EXEC and ET_DYN files.
	if f.Type == elf.ET_NONE || f.Type == elf.ET_REL || f.Type == elf.ET_CORE {
		return KindUnknown
	}
	if f.Type != elf.ET_DYN {
		return KindProgram
	}
	if slices.ContainsFunc(f.Progs, func(p *elf.Prog) bool { return p.Type == elf.PT_INTERP }) {
		return KindProgram
	}
	pie, err := isPIE(f)
	if err != nil || pie {
		return KindProgram
	}
	return KindLibrary
}

// isPIE reports if the DF_1_PIE flag is set in the dynamic segment. It reads
// the PT_DYNAMIC segment, as the kernel does, and not the .dynamic section,
// which a stripped binary can lack. It returns errMalformed when the segment
// is too large, is cut short, has more than one DT_FLAGS_1 entry, or does not
// end with a DT_NULL entry.
func isPIE(f *elf.File) (bool, error) {
	i := slices.IndexFunc(f.Progs, func(p *elf.Prog) bool { return p.Type == elf.PT_DYNAMIC })
	if i < 0 {
		return false, nil
	}
	entries, err := readDynamic(f, f.Progs[i])
	if err != nil {
		return false, err
	}

	var flags1 uint64
	found := false
	for _, d := range entries {
		tag := elf.DynTag(d.Tag)
		if tag == elf.DT_NULL {
			return flags1&uint64(elf.DF_1_PIE) != 0, nil
		}
		if tag == elf.DT_FLAGS_1 {
			if found {
				return false, errMalformed
			}
			flags1, found = d.Val, true
		}
	}
	return false, errMalformed
}

// readDynamic returns the entries of the dynamic segment p, for both
// classes of ELF files.
func readDynamic(f *elf.File, p *elf.Prog) ([]elf.Dyn64, error) {
	is32 := f.Class == elf.ELFCLASS32
	entrySize := binary.Size(elf.Dyn64{})
	if is32 {
		entrySize = binary.Size(elf.Dyn32{})
	}
	if p.Filesz > maxDynamicSize {
		return nil, errMalformed
	}
	size := int(p.Filesz)
	if size%entrySize != 0 {
		return nil, errMalformed
	}
	data := make([]byte, size)
	if _, err := io.ReadFull(p.Open(), data); err != nil {
		return nil, errMalformed
	}

	count := size / entrySize
	if !is32 {
		entries := make([]elf.Dyn64, count)
		if _, err := binary.Decode(data, f.ByteOrder, entries); err != nil {
			return nil, err
		}
		return entries, nil
	}

	entries32 := make([]elf.Dyn32, count)
	if _, err := binary.Decode(data, f.ByteOrder, entries32); err != nil {
		return nil, err
	}
	entries := make([]elf.Dyn64, 0, count)
	for _, d := range entries32 {
		entries = append(entries, elf.Dyn64{Tag: int64(d.Tag), Val: uint64(d.Val)})
	}
	return entries, nil
}
