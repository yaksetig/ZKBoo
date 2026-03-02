package circom

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

// Witness binary format constants
const (
	wtnsMagic   = 0x736e7477 // "wtns" in little-endian
	wtnsVersion = 2
)

// ParseWitness reads a Circom .wtns binary file and returns the witness values.
func ParseWitness(path string) (*Witness, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open witness file: %w", err)
	}
	defer f.Close()
	return parseWitnessReader(f)
}

// ParseWitnessBytes parses a witness binary from a byte slice.
func ParseWitnessBytes(data []byte) (*Witness, error) {
	return parseWitnessReader(&byteReader{data: data})
}

func parseWitnessReader(r io.Reader) (*Witness, error) {
	// Read magic
	var magic uint32
	if err := binary.Read(r, binary.LittleEndian, &magic); err != nil {
		return nil, fmt.Errorf("read magic: %w", err)
	}
	if magic != wtnsMagic {
		return nil, fmt.Errorf("invalid magic: got 0x%x, want 0x%x", magic, wtnsMagic)
	}

	// Read version
	var version uint32
	if err := binary.Read(r, binary.LittleEndian, &version); err != nil {
		return nil, fmt.Errorf("read version: %w", err)
	}
	if version != wtnsVersion {
		return nil, fmt.Errorf("unsupported version: %d", version)
	}

	// Read number of sections
	var nSections uint32
	if err := binary.Read(r, binary.LittleEndian, &nSections); err != nil {
		return nil, fmt.Errorf("read nSections: %w", err)
	}

	// Read sections
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
			return nil, fmt.Errorf("read section data (type %d): %w", sType, err)
		}
		sections[sType] = data
	}

	// Parse header
	headerData, ok := sections[1]
	if !ok {
		return nil, fmt.Errorf("missing header section")
	}
	if len(headerData) < 4 {
		return nil, fmt.Errorf("header too short")
	}
	fieldSize := binary.LittleEndian.Uint32(headerData[0:4])
	if uint32(len(headerData)) < 4+fieldSize+4 {
		return nil, fmt.Errorf("header too short for field size %d", fieldSize)
	}
	prime := make([]byte, fieldSize)
	copy(prime, headerData[4:4+fieldSize])
	nWitness := binary.LittleEndian.Uint32(headerData[4+fieldSize:])

	// Parse data section
	dataSection, ok := sections[2]
	if !ok {
		return nil, fmt.Errorf("missing data section")
	}

	values := make([]FieldElement, nWitness)
	for i := uint32(0); i < nWitness; i++ {
		offset := int(i) * int(fieldSize)
		if offset+int(fieldSize) > len(dataSection) {
			return nil, fmt.Errorf("data section too short at witness %d", i)
		}
		values[i] = FieldElementFromBytes(dataSection[offset : offset+int(fieldSize)])
	}

	return &Witness{
		Prime:  prime,
		Values: values,
	}, nil
}
