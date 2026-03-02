package circom

// R1CSCircuit represents a parsed R1CS constraint system.
type R1CSCircuit struct {
	Prime        []byte // field prime (little-endian)
	NWires       uint32
	NPubOut      uint32
	NPubIn       uint32
	NPrivIn      uint32
	NConstraints uint32
	Constraints  []Constraint
}

// Constraint represents a single R1CS constraint: <A,w> * <B,w> = <C,w>.
type Constraint struct {
	A []Term
	B []Term
	C []Term
}

// Term represents a coefficient*wire pair in a linear combination.
type Term struct {
	WireID      uint32
	Coefficient FieldElement
}

// Witness holds the full witness vector (including w[0]=1, public outputs,
// public inputs, and private signals).
type Witness struct {
	Prime  []byte
	Values []FieldElement
}

// ArithView records one party's computation trace in an arithmetic ZKBoo round.
type ArithView struct {
	// InputShare holds this party's additive share of the witness.
	InputShare []FieldElement
	// MulOutputs holds the output of each multiplication gate for this party.
	MulOutputs []FieldElement
}

// ArithCommitment is the first message of one ZKBoo round (all 3 parties).
type ArithCommitment struct {
	// OutputShares holds each party's share of the public output wires.
	OutputShares [3][]FieldElement
	// Hashes holds the SHA-256 commitment of each party's view.
	Hashes [3][32]byte
}

// ArithResponse is the response to the challenge for one ZKBoo round.
type ArithResponse struct {
	E     int // challenge value in {0, 1, 2}
	Key0  [16]byte
	Key1  [16]byte
	View0 ArithView
	View1 ArithView
	Rand0 [4]byte
	Rand1 [4]byte
}

// CircomProof is the full proof for an R1CS circuit, consisting of
// NumRounds independent ZKBoo rounds.
type CircomProof struct {
	NumRounds   int
	NWires      uint32
	NPubOut     uint32
	Commitments []ArithCommitment
	Responses   []ArithResponse
}
