package imagescan_test

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"io"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kubewarden/runtime-enforcer/internal/imagescan"
	ist "github.com/kubewarden/runtime-enforcer/internal/imagescan/imagescantest"
)

// The tests in this file cover the code of classify. The parse of the ELF
// headers belongs to debug/elf and to elfutil, which have their own tests.

// TestClassifyClassesAndByteOrders covers the decoding of the dynamic
// segment, which depends on the class and on the byte order of the file.
func TestClassifyClassesAndByteOrders(t *testing.T) {
	t.Parallel()

	formats := []struct {
		name  string
		class elf.Class
		data  elf.Data
	}{
		{name: "32-bit little-endian", class: elf.ELFCLASS32, data: elf.ELFDATA2LSB},
		{name: "32-bit big-endian", class: elf.ELFCLASS32, data: elf.ELFDATA2MSB},
		{name: "64-bit little-endian", class: elf.ELFCLASS64, data: elf.ELFDATA2LSB},
		{name: "64-bit big-endian", class: elf.ELFCLASS64, data: elf.ELFDATA2MSB},
	}
	files := []struct {
		name string
		spec ist.ELFSpec
		kind imagescan.Kind
	}{
		{
			name: "static PIE",
			spec: ist.ELFSpec{Type: elf.ET_DYN, Dynamic: true, Flags1: elf.DF_1_NOW | elf.DF_1_PIE},
			kind: imagescan.KindProgram,
		},
		{
			name: "library with flags",
			spec: ist.ELFSpec{Type: elf.ET_DYN, Dynamic: true, Flags1: elf.DF_1_NOW},
			kind: imagescan.KindLibrary,
		},
	}

	for _, format := range formats {
		for _, file := range files {
			t.Run(format.name+"/"+file.name, func(t *testing.T) {
				t.Parallel()

				spec := file.spec
				spec.Class, spec.Data = format.class, format.data
				kind, err := imagescan.Classify(bytes.NewReader(ist.ELF(spec)))
				require.NoError(t, err)
				assert.Equal(t, file.kind, kind)
			})
		}
	}
}

// library returns a 64-bit little-endian shared library. Its only program
// header is the PT_DYNAMIC segment, which is at the end of the file and has
// only a DT_NULL entry.
func library() []byte {
	return ist.ELF(ist.ELFSpec{Type: elf.ET_DYN, Dynamic: true})
}

// withDynamic changes the program header of the dynamic segment of library.
func withDynamic(t *testing.T, data []byte, change func(p *elf.Prog64)) []byte {
	t.Helper()

	start := binary.Size(elf.Header64{})
	var p elf.Prog64
	size, err := binary.Decode(data[start:], binary.LittleEndian, &p)
	require.NoError(t, err)
	require.Equal(t, uint32(elf.PT_DYNAMIC), p.Type)
	change(&p)
	_, err = binary.Encode(data[start:start+size], binary.LittleEndian, &p)
	require.NoError(t, err)
	return data
}

// withDynamicEntries returns library, with the given entries in its dynamic
// segment.
func withDynamicEntries(t *testing.T, entries ...elf.Dyn64) []byte {
	t.Helper()

	start := binary.Size(elf.Header64{}) + binary.Size(elf.Prog64{})
	data, err := binary.Append(library()[:start], binary.LittleEndian, entries)
	require.NoError(t, err)
	return withDynamic(t, data, func(p *elf.Prog64) {
		p.Filesz = uint64(len(entries) * binary.Size(elf.Dyn64{}))
	})
}

func TestClassifyDynamicSegment(t *testing.T) {
	t.Parallel()

	lib := library()
	entrySize := uint64(binary.Size(elf.Dyn64{}))

	tests := []struct {
		name string
		data []byte
		kind imagescan.Kind
	}{
		{
			// The control case: the other rows change this file.
			name: "valid library",
			data: library(),
			kind: imagescan.KindLibrary,
		},
		{
			name: "library with other dynamic entries",
			data: withDynamicEntries(t,
				elf.Dyn64{Tag: int64(elf.DT_NEEDED), Val: 1},
				elf.Dyn64{Tag: int64(elf.DT_FLAGS_1), Val: uint64(elf.DF_1_NOW)},
				elf.Dyn64{Tag: int64(elf.DT_NULL)},
			),
			kind: imagescan.KindLibrary,
		},
		{
			name: "larger than the limit",
			data: withDynamic(t, library(), func(p *elf.Prog64) { p.Filesz = imagescan.MaxDynamicSize + entrySize }),
			kind: imagescan.KindProgram,
		},
		{
			name: "size not a multiple of the entry size",
			data: withDynamic(t, library(), func(p *elf.Prog64) { p.Filesz = entrySize + 1 }),
			kind: imagescan.KindProgram,
		},
		{
			name: "cut short",
			data: lib[:len(lib)-1],
			kind: imagescan.KindProgram,
		},
		{
			name: "empty",
			data: withDynamic(t, library(), func(p *elf.Prog64) { p.Filesz = 0 }),
			kind: imagescan.KindProgram,
		},
		{
			name: "without DT_NULL",
			data: withDynamicEntries(t, elf.Dyn64{Tag: int64(elf.DT_FLAGS_1), Val: uint64(elf.DF_1_NOW)}),
			kind: imagescan.KindProgram,
		},
		{
			// A later DT_FLAGS_1 entry must not hide the DF_1_PIE flag of an
			// earlier one.
			name: "DT_FLAGS_1 with DF_1_PIE, then DT_FLAGS_1 without it",
			data: withDynamicEntries(t,
				elf.Dyn64{Tag: int64(elf.DT_FLAGS_1), Val: uint64(elf.DF_1_PIE)},
				elf.Dyn64{Tag: int64(elf.DT_FLAGS_1), Val: uint64(elf.DF_1_NOW)},
				elf.Dyn64{Tag: int64(elf.DT_NULL)},
			),
			kind: imagescan.KindProgram,
		},
		{
			name: "DT_FLAGS_1 without DF_1_PIE, then DT_FLAGS_1 with it",
			data: withDynamicEntries(t,
				elf.Dyn64{Tag: int64(elf.DT_FLAGS_1), Val: uint64(elf.DF_1_NOW)},
				elf.Dyn64{Tag: int64(elf.DT_FLAGS_1), Val: uint64(elf.DF_1_PIE)},
				elf.Dyn64{Tag: int64(elf.DT_NULL)},
			),
			kind: imagescan.KindProgram,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			kind, err := imagescan.Classify(bytes.NewReader(tt.data))
			require.NoError(t, err)
			assert.Equal(t, tt.kind, kind)
		})
	}
}

// farthestReader records the end of the farthest read at an offset.
type farthestReader struct {
	*bytes.Reader

	farthest int64
}

func (f *farthestReader) ReadAt(p []byte, off int64) (int, error) {
	n, err := f.Reader.ReadAt(p, off)
	f.farthest = max(f.farthest, off+int64(n))
	return n, err
}

func TestClassifyReadsOnlyWhatItNeeds(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		data     []byte
		farthest int
		kind     imagescan.Kind
	}{
		{
			name:     "library",
			data:     library(),
			farthest: len(library()),
			kind:     imagescan.KindLibrary,
		},
		{
			name: "dynamic segment larger than the limit",
			data: withDynamic(t, library(), func(p *elf.Prog64) {
				p.Filesz = imagescan.MaxDynamicSize + uint64(binary.Size(elf.Dyn64{}))
			}),
			farthest: binary.Size(elf.Header64{}) + binary.Size(elf.Prog64{}),
			kind:     imagescan.KindProgram,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// A large tail must never be read.
			r := &farthestReader{Reader: bytes.NewReader(slices.Concat(tt.data, make([]byte, 1<<20)))}
			kind, err := imagescan.Classify(r)
			require.NoError(t, err)
			assert.Equal(t, tt.kind, kind)
			assert.LessOrEqual(t, r.farthest, int64(tt.farthest))
		})
	}
}

func TestClassifyELFThatDoesNotParse(t *testing.T) {
	t.Parallel()

	kind, err := imagescan.Classify(bytes.NewReader(library()[:binary.Size(elf.Header64{})-1]))
	require.NoError(t, err)
	assert.Equal(t, imagescan.KindProgram, kind)
}

// panicReader panics on reads at an offset, as debug/elf can do on a
// hostile file.
type panicReader struct {
	*bytes.Reader
}

func (panicReader) ReadAt([]byte, int64) (int, error) {
	panic("hostile file")
}

func TestClassifyRecoversFromPanics(t *testing.T) {
	t.Parallel()

	kind, err := imagescan.Classify(panicReader{bytes.NewReader(library())})
	require.NoError(t, err)
	assert.Equal(t, imagescan.KindProgram, kind)
}

var errReadTooFar = errors.New("read after the limit")

// limitedReader cannot read at an offset, and fails when a read goes after
// the first limit bytes of r.
type limitedReader struct {
	r     io.Reader
	limit int
}

func (l *limitedReader) Read(p []byte) (int, error) {
	if l.limit <= 0 {
		return 0, errReadTooFar
	}
	if len(p) > l.limit {
		p = p[:l.limit]
	}
	n, err := l.r.Read(p)
	l.limit -= n
	return n, err
}

func TestClassifyWithoutRandomAccess(t *testing.T) {
	t.Parallel()

	data := library()
	kind, err := imagescan.Classify(&limitedReader{r: bytes.NewReader(data), limit: len(data)})
	require.NoError(t, err)
	assert.Equal(t, imagescan.KindProgram, kind)
}

func TestClassifyReturnsReadErrors(t *testing.T) {
	t.Parallel()

	_, err := imagescan.Classify(&limitedReader{r: bytes.NewReader(library()), limit: 2})
	require.ErrorIs(t, err, errReadTooFar)
}
