package circom

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

// R1CS binary format constants
const (
	r1csMagic      = 0x73633172 // "r1cs" in little-endian
	r1csVersion    = 1
	sectionHeader  = 1
	sectionConst   = 2
	sectionW2L     = 3
)

// ParseR1CS reads a Circom .r1cs binary file and returns the parsed circuit.
func ParseR1CS(path string) (*R1CSCircuit, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open r1cs file: %w", err)
	}
	defer f.Close()
	return parseR1CSReader(f)
}

// ParseR1CSBytes parses an R1CS binary from a byte slice.
func ParseR1CSBytes(data []byte) (*R1CSCircuit, error) {
	return parseR1CSReader(&byteReader{data: data})
}

type byteReader struct {
	data []byte
	pos  int
}

func (b *byteReader) Read(p []byte) (int, error) {
	if b.pos >= len(b.data) {
		return 0, io.EOF
	}
	n := copy(p, b.data[b.pos:])
	b.pos += n
	return n, nil
}

func parseR1CSReader(r io.Reader) (*R1CSCircuit, error) {
	// Read magic
	var magic uint32
	if err := binary.Read(r, binary.LittleEndian, &magic); err != nil {
		return nil, fmt.Errorf("read magic: %w", err)
	}
	if magic != r1csMagic {
		return nil, fmt.Errorf("invalid magic: got 0x%x, want 0x%x", magic, r1csMagic)
	}

	// Read version
	var version uint32
	if err := binary.Read(r, binary.LittleEndian, &version); err != nil {
		return nil, fmt.Errorf("read version: %w", err)
	}
	if version != r1csVersion {
		return nil, fmt.Errorf("unsupported version: %d", version)
	}

	// Read number of sections
	var nSections uint32
	if err := binary.Read(r, binary.LittleEndian, &nSections); err != nil {
		return nil, fmt.Errorf("read nSections: %w", err)
	}

	// Read all sections into a map
	sections := make(map[uint32][]byte)
	for i := uint32(0); i < nSections; i++ {
		var sType uint32
		if err := binary.Read(r, binary.LittleEndian, &sType); err != nil {
			return nil, fmt.Errorf("read section type: %w", err)
		}
		var sSize uint64
		if err := binary.Read(r, binary.LittleEndian, &sSize); err != nil {
			return nil, fmt.Errorf("read section size: %w", err)
		}
		data := make([]byte, sSize)
		if _, err := io.ReadFull(r, data); err != nil {
			return nil, fmt.Errorf("read section data (type %d, size %d): %w", sType, sSize, err)
		}
		sections[sType] = data
	}

	// Parse header section
	headerData, ok := sections[sectionHeader]
	if !ok {
		return nil, fmt.Errorf("missing header section")
	}
	circuit, fieldSize, err := parseHeader(headerData)
	if err != nil {
		return nil, fmt.Errorf("parse header: %w", err)
	}

	// Parse constraints section
	constData, ok := sections[sectionConst]
	if !ok {
		return nil, fmt.Errorf("missing constraints section")
	}
	constraints, err := parseConstraints(constData, circuit.NConstraints, fieldSize)
	if err != nil {
		return nil, fmt.Errorf("parse constraints: %w", err)
	}
	circuit.Constraints = constraints

	return circuit, nil
}

func parseHeader(data []byte) (*R1CSCircuit, uint32, error) {
	if len(data) < 4 {
		return nil, 0, fmt.Errorf("header too short")
	}
	pos := 0

	fieldSize := binary.LittleEndian.Uint32(data[pos:])
	pos += 4

	if uint32(len(data)) < 4+fieldSize+4*4+8+4 {
		return nil, 0, fmt.Errorf("header too short for field size %d", fieldSize)
	}

	prime := make([]byte, fieldSize)
	copy(prime, data[pos:pos+int(fieldSize)])
	pos += int(fieldSize)

	nWires := binary.LittleEndian.Uint32(data[pos:])
	pos += 4
	nPubOut := binary.LittleEndian.Uint32(data[pos:])
	pos += 4
	nPubIn := binary.LittleEndian.Uint32(data[pos:])
	pos += 4
	nPrivIn := binary.LittleEndian.Uint32(data[pos:])
	pos += 4
	// nLabels (uint64) - skip
	pos += 8
	nConstraints := binary.LittleEndian.Uint32(data[pos:])

	return &R1CSCircuit{
		Prime:        prime,
		NWires:       nWires,
		NPubOut:      nPubOut,
		NPubIn:       nPubIn,
		NPrivIn:      nPrivIn,
		NConstraints: nConstraints,
	}, fieldSize, nil
}

func parseConstraints(data []byte, nConstraints, fieldSize uint32) ([]Constraint, error) {
	constraints := make([]Constraint, nConstraints)
	pos := 0

	for i := uint32(0); i < nConstraints; i++ {
		var err error
		var a, b, c []Term

		a, pos, err = parseLinearCombination(data, pos, fieldSize)
		if err != nil {
			return nil, fmt.Errorf("constraint %d, A: %w", i, err)
		}
		b, pos, err = parseLinearCombination(data, pos, fieldSize)
		if err != nil {
			return nil, fmt.Errorf("constraint %d, B: %w", i, err)
		}
		c, pos, err = parseLinearCombination(data, pos, fieldSize)
		if err != nil {
			return nil, fmt.Errorf("constraint %d, C: %w", i, err)
		}

		constraints[i] = Constraint{A: a, B: b, C: c}
	}

	return constraints, nil
}

func parseLinearCombination(data []byte, pos int, fieldSize uint32) ([]Term, int, error) {
	if pos+4 > len(data) {
		return nil, pos, fmt.Errorf("unexpected end reading nTerms at pos %d", pos)
	}
	nTerms := binary.LittleEndian.Uint32(data[pos:])
	pos += 4

	terms := make([]Term, nTerms)
	for j := uint32(0); j < nTerms; j++ {
		if pos+4+int(fieldSize) > len(data) {
			return nil, pos, fmt.Errorf("unexpected end reading term %d at pos %d", j, pos)
		}
		wireID := binary.LittleEndian.Uint32(data[pos:])
		pos += 4
		coeff := FieldElementFromBytes(data[pos : pos+int(fieldSize)])
		pos += int(fieldSize)
		terms[j] = Term{WireID: wireID, Coefficient: coeff}
	}
	return terms, pos, nil
}
