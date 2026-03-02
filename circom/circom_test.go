package circom

import (
	"encoding/binary"
	"math/big"
	"os"
	"testing"
)

// TestFieldArithmetic tests basic field operations.
func TestFieldArithmetic(t *testing.T) {
	a := NewFieldElement(big.NewInt(7))
	b := NewFieldElement(big.NewInt(11))

	// Addition
	sum := a.Add(b)
	if !sum.Equal(NewFieldElement(big.NewInt(18))) {
		t.Fatalf("7 + 11 = %s, want 18", sum)
	}

	// Multiplication
	prod := a.Mul(b)
	if !prod.Equal(NewFieldElement(big.NewInt(77))) {
		t.Fatalf("7 * 11 = %s, want 77", prod)
	}

	// Subtraction
	diff := b.Sub(a)
	if !diff.Equal(NewFieldElement(big.NewInt(4))) {
		t.Fatalf("11 - 7 = %s, want 4", diff)
	}

	// Negation
	neg := a.Neg()
	if !a.Add(neg).IsZero() {
		t.Fatalf("7 + (-7) = %s, want 0", a.Add(neg))
	}

	// Modular reduction
	pMinus1 := NewFieldElement(new(big.Int).Sub(FieldPrime(), big.NewInt(1)))
	one := One()
	shouldBeZero := pMinus1.Add(one)
	if !shouldBeZero.IsZero() {
		t.Fatalf("(p-1) + 1 = %s, want 0", shouldBeZero)
	}
}

// TestFieldSerialization tests field element byte serialization.
func TestFieldSerialization(t *testing.T) {
	a := NewFieldElement(big.NewInt(0x1234567890abcdef))
	b := a.Bytes()
	c := FieldElementFromBytes(b[:])
	if !a.Equal(c) {
		t.Fatalf("round-trip failed: %s != %s", a, c)
	}
}

// TestSecretSharing tests witness sharing and reconstruction.
func TestSecretSharing(t *testing.T) {
	w := []FieldElement{
		One(),
		NewFieldElement(big.NewInt(42)),
		NewFieldElement(big.NewInt(1337)),
	}

	shares, err := shareWitness(w)
	if err != nil {
		t.Fatal(err)
	}

	// Verify reconstruction
	for i, val := range w {
		recon := reconstructShares(shares[0][i], shares[1][i], shares[2][i])
		if !recon.Equal(val) {
			t.Fatalf("wire %d: reconstructed %s, want %s", i, recon, val)
		}
	}
}

// TestMPCMul3 tests 3-party secure multiplication.
func TestMPCMul3(t *testing.T) {
	x := NewFieldElement(big.NewInt(7))
	y := NewFieldElement(big.NewInt(11))
	expected := x.Mul(y) // 77

	// Share x and y
	xShares, err := shareWitness([]FieldElement{x})
	if err != nil {
		t.Fatal(err)
	}
	yShares, err := shareWitness([]FieldElement{y})
	if err != nil {
		t.Fatal(err)
	}

	var xS, yS [3]FieldElement
	for i := 0; i < 3; i++ {
		xS[i] = xShares[i][0]
		yS[i] = yShares[i][0]
	}

	// Generate randomness
	var keys [3][16]byte
	for i := 0; i < 3; i++ {
		keys[i] = [16]byte{byte(i + 1)}
	}
	var randomness [3][]byte
	for i := 0; i < 3; i++ {
		randomness[i], err = expandRandomness(keys[i], FieldSize)
		if err != nil {
			t.Fatal(err)
		}
	}

	offset := 0
	z := mpcMul3(xS, yS, randomness, &offset)

	// Reconstruct
	result := reconstructShares(z[0], z[1], z[2])
	if !result.Equal(expected) {
		t.Fatalf("MPC mul: %s * %s = %s, want %s", x, y, result, expected)
	}
}

// buildSimpleCircuit creates a trivial R1CS circuit:
//
//	Circuit: prove knowledge of x such that x * x = pubOut
//	Wire 0: constant 1
//	Wire 1: public output (x*x)
//	Wire 2: private input x
//
//	Constraint: A=[wire2] * B=[wire2] = C=[wire1]
func buildSimpleCircuit(x int64) (*R1CSCircuit, *Witness) {
	xVal := NewFieldElement(big.NewInt(x))
	xSquared := xVal.Mul(xVal)

	circuit := &R1CSCircuit{
		NWires:       3,
		NPubOut:      1,
		NPubIn:       0,
		NPrivIn:      1,
		NConstraints: 1,
		Constraints: []Constraint{
			{
				A: []Term{{WireID: 2, Coefficient: One()}},
				B: []Term{{WireID: 2, Coefficient: One()}},
				C: []Term{{WireID: 1, Coefficient: One()}},
			},
		},
	}

	witness := &Witness{
		Values: []FieldElement{One(), xSquared, xVal},
	}

	return circuit, witness
}

// TestSimpleCircuitProveVerify tests a full prove/verify cycle with a trivial circuit.
func TestSimpleCircuitProveVerify(t *testing.T) {
	circuit, witness := buildSimpleCircuit(7)

	proof, err := Prove(circuit, witness)
	if err != nil {
		t.Fatalf("prove: %v", err)
	}

	// Public output = 49
	publicOutputs := []FieldElement{witness.Values[1]}

	ok, err := Verify(circuit, proof, publicOutputs)
	if err != nil {
		t.Fatalf("verify error: %v", err)
	}
	if !ok {
		t.Fatal("verification failed")
	}
}

// buildMultiConstraintCircuit creates a more complex circuit:
//
//	Prove knowledge of a, b such that a * b = c AND a + b = d
//
//	Wire 0: constant 1
//	Wire 1: public output c (= a*b)
//	Wire 2: public output d (= a+b)
//	Wire 3: private input a
//	Wire 4: private input b
//	Wire 5: intermediate (a+b)
//
//	Constraint 0: A=[w3] * B=[w4] = C=[w1]          (a * b = c)
//	Constraint 1: A=[w3 + w4] * B=[1*w0] = C=[w2]   ((a+b) * 1 = d)
func buildMultiConstraintCircuit(a, b int64) (*R1CSCircuit, *Witness) {
	aVal := NewFieldElement(big.NewInt(a))
	bVal := NewFieldElement(big.NewInt(b))
	cVal := aVal.Mul(bVal) // a * b
	dVal := aVal.Add(bVal) // a + b

	circuit := &R1CSCircuit{
		NWires:       5,
		NPubOut:      2,
		NPubIn:       0,
		NPrivIn:      2,
		NConstraints: 2,
		Constraints: []Constraint{
			{
				// a * b = c
				A: []Term{{WireID: 3, Coefficient: One()}},
				B: []Term{{WireID: 4, Coefficient: One()}},
				C: []Term{{WireID: 1, Coefficient: One()}},
			},
			{
				// (a + b) * 1 = d
				A: []Term{
					{WireID: 3, Coefficient: One()},
					{WireID: 4, Coefficient: One()},
				},
				B: []Term{{WireID: 0, Coefficient: One()}},
				C: []Term{{WireID: 2, Coefficient: One()}},
			},
		},
	}

	witness := &Witness{
		Values: []FieldElement{One(), cVal, dVal, aVal, bVal},
	}

	return circuit, witness
}

// TestMultiConstraintProveVerify tests a circuit with multiple constraints.
func TestMultiConstraintProveVerify(t *testing.T) {
	circuit, witness := buildMultiConstraintCircuit(3, 5)

	proof, err := Prove(circuit, witness)
	if err != nil {
		t.Fatalf("prove: %v", err)
	}

	// Public outputs: c=15, d=8
	publicOutputs := []FieldElement{witness.Values[1], witness.Values[2]}

	ok, err := Verify(circuit, proof, publicOutputs)
	if err != nil {
		t.Fatalf("verify error: %v", err)
	}
	if !ok {
		t.Fatal("verification failed")
	}
}

// TestWrongWitnessRejected ensures that an invalid witness is rejected during proving.
func TestWrongWitnessRejected(t *testing.T) {
	circuit, _ := buildSimpleCircuit(7)

	// Provide a wrong witness: claim 7*7 = 50 (wrong)
	badWitness := &Witness{
		Values: []FieldElement{
			One(),
			NewFieldElement(big.NewInt(50)), // wrong output
			NewFieldElement(big.NewInt(7)),
		},
	}

	_, err := Prove(circuit, badWitness)
	if err == nil {
		t.Fatal("expected error for invalid witness, got nil")
	}
}

// TestWrongPublicOutputRejected ensures that wrong public outputs fail verification.
func TestWrongPublicOutputRejected(t *testing.T) {
	circuit, witness := buildSimpleCircuit(7)

	proof, err := Prove(circuit, witness)
	if err != nil {
		t.Fatalf("prove: %v", err)
	}

	// Verify with wrong public output
	wrongOutputs := []FieldElement{NewFieldElement(big.NewInt(50))}
	ok, err := Verify(circuit, proof, wrongOutputs)
	if err == nil && ok {
		t.Fatal("verification should have failed with wrong public output")
	}
}

// TestProofSerialization tests JSON serialization round-trip.
func TestProofSerialization(t *testing.T) {
	circuit, witness := buildSimpleCircuit(7)

	proof, err := Prove(circuit, witness)
	if err != nil {
		t.Fatalf("prove: %v", err)
	}

	publicOutputs := []FieldElement{witness.Values[1]}

	// Save to temp file
	tmpFile, err := os.CreateTemp("", "zkboo_proof_*.json")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	if err := SaveProof(tmpFile.Name(), proof, publicOutputs); err != nil {
		t.Fatalf("save: %v", err)
	}

	// Load back
	loadedProof, loadedOutputs, err := LoadProof(tmpFile.Name())
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	// Verify loaded proof
	ok, err := Verify(circuit, loadedProof, loadedOutputs)
	if err != nil {
		t.Fatalf("verify loaded: %v", err)
	}
	if !ok {
		t.Fatal("loaded proof verification failed")
	}
}

// TestR1CSParser tests the binary R1CS parser with a hand-crafted binary.
func TestR1CSParser(t *testing.T) {
	// Build a minimal R1CS binary for the simple x*x=y circuit
	data := buildR1CSBinary(t)

	circuit, err := ParseR1CSBytes(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if circuit.NWires != 3 {
		t.Fatalf("nWires: got %d, want 3", circuit.NWires)
	}
	if circuit.NConstraints != 1 {
		t.Fatalf("nConstraints: got %d, want 1", circuit.NConstraints)
	}
	if circuit.NPubOut != 1 {
		t.Fatalf("nPubOut: got %d, want 1", circuit.NPubOut)
	}
	if len(circuit.Constraints) != 1 {
		t.Fatalf("constraints: got %d, want 1", len(circuit.Constraints))
	}

	c := circuit.Constraints[0]
	if len(c.A) != 1 || c.A[0].WireID != 2 {
		t.Fatalf("constraint A: unexpected %+v", c.A)
	}
	if len(c.B) != 1 || c.B[0].WireID != 2 {
		t.Fatalf("constraint B: unexpected %+v", c.B)
	}
	if len(c.C) != 1 || c.C[0].WireID != 1 {
		t.Fatalf("constraint C: unexpected %+v", c.C)
	}
}

// TestWitnessParser tests the binary witness parser with a hand-crafted binary.
func TestWitnessParser(t *testing.T) {
	data := buildWtnsBinary(t, 7)

	witness, err := ParseWitnessBytes(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if len(witness.Values) != 3 {
		t.Fatalf("nWitness: got %d, want 3", len(witness.Values))
	}

	// w[0] = 1
	if !witness.Values[0].Equal(One()) {
		t.Fatalf("w[0] = %s, want 1", witness.Values[0])
	}
	// w[1] = 49
	if !witness.Values[1].Equal(NewFieldElement(big.NewInt(49))) {
		t.Fatalf("w[1] = %s, want 49", witness.Values[1])
	}
	// w[2] = 7
	if !witness.Values[2].Equal(NewFieldElement(big.NewInt(7))) {
		t.Fatalf("w[2] = %s, want 7", witness.Values[2])
	}
}

// TestR1CSParserEndToEnd parses binary R1CS + witness and runs prove/verify.
func TestR1CSParserEndToEnd(t *testing.T) {
	r1csData := buildR1CSBinary(t)
	wtnsData := buildWtnsBinary(t, 7)

	circuit, err := ParseR1CSBytes(r1csData)
	if err != nil {
		t.Fatalf("parse r1cs: %v", err)
	}

	witness, err := ParseWitnessBytes(wtnsData)
	if err != nil {
		t.Fatalf("parse witness: %v", err)
	}

	proof, err := Prove(circuit, witness)
	if err != nil {
		t.Fatalf("prove: %v", err)
	}

	publicOutputs := []FieldElement{witness.Values[1]}
	ok, err := Verify(circuit, proof, publicOutputs)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !ok {
		t.Fatal("verification failed")
	}
}

// --- helpers to build binary test data ---

func buildR1CSBinary(t *testing.T) []byte {
	t.Helper()

	// Simple circuit: x * x = y
	// Wire 0: const 1, Wire 1: pub out (y), Wire 2: priv in (x)
	// Constraint: [w2]*[w2] = [w1]

	fieldSize := uint32(32)
	prime := FieldPrime().Bytes()
	// Convert to LE
	primeLE := make([]byte, fieldSize)
	for i, b := range prime {
		primeLE[len(prime)-1-i] = b
	}

	// Build header section
	var header []byte
	header = appendU32LE(header, fieldSize)
	header = append(header, primeLE...)
	header = appendU32LE(header, 3)  // nWires
	header = appendU32LE(header, 1)  // nPubOut
	header = appendU32LE(header, 0)  // nPubIn
	header = appendU32LE(header, 1)  // nPrivIn
	header = appendU64LE(header, 3)  // nLabels
	header = appendU32LE(header, 1)  // nConstraints

	// Build constraints section
	var constraints []byte
	one := oneLE(fieldSize)

	// A: 1 term, wire 2, coeff 1
	constraints = appendU32LE(constraints, 1)
	constraints = appendU32LE(constraints, 2)
	constraints = append(constraints, one...)

	// B: 1 term, wire 2, coeff 1
	constraints = appendU32LE(constraints, 1)
	constraints = appendU32LE(constraints, 2)
	constraints = append(constraints, one...)

	// C: 1 term, wire 1, coeff 1
	constraints = appendU32LE(constraints, 1)
	constraints = appendU32LE(constraints, 1)
	constraints = append(constraints, one...)

	// Build file
	var file []byte
	file = appendU32LE(file, r1csMagic)
	file = appendU32LE(file, r1csVersion)
	file = appendU32LE(file, 2) // 2 sections (header + constraints)

	// Section 1: header
	file = appendU32LE(file, sectionHeader)
	file = appendU64LE(file, uint64(len(header)))
	file = append(file, header...)

	// Section 2: constraints
	file = appendU32LE(file, sectionConst)
	file = appendU64LE(file, uint64(len(constraints)))
	file = append(file, constraints...)

	return file
}

func buildWtnsBinary(t *testing.T, x int64) []byte {
	t.Helper()

	fieldSize := uint32(32)
	prime := FieldPrime().Bytes()
	primeLE := make([]byte, fieldSize)
	for i, b := range prime {
		primeLE[len(prime)-1-i] = b
	}

	xVal := NewFieldElement(big.NewInt(x))
	xSquared := xVal.Mul(xVal)

	// w[0]=1, w[1]=x*x, w[2]=x
	vals := []FieldElement{One(), xSquared, xVal}

	// Header section
	var header []byte
	header = appendU32LE(header, fieldSize)
	header = append(header, primeLE...)
	header = appendU32LE(header, uint32(len(vals)))

	// Data section
	var data []byte
	for _, v := range vals {
		b := v.Bytes()
		data = append(data, b[:]...)
	}

	// Build file
	var file []byte
	file = appendU32LE(file, wtnsMagic)
	file = appendU32LE(file, wtnsVersion)
	file = appendU32LE(file, 2) // 2 sections

	// Section 1: header
	file = appendU32LE(file, 1)
	file = appendU64LE(file, uint64(len(header)))
	file = append(file, header...)

	// Section 2: data
	file = appendU32LE(file, 2)
	file = appendU64LE(file, uint64(len(data)))
	file = append(file, data...)

	return file
}

func appendU32LE(buf []byte, v uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return append(buf, b...)
}

func appendU64LE(buf []byte, v uint64) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, v)
	return append(buf, b...)
}

func oneLE(fieldSize uint32) []byte {
	b := make([]byte, fieldSize)
	b[0] = 1
	return b
}
