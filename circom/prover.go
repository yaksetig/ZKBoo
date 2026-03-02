package circom

import (
	"crypto/rand"
	"fmt"
)

// NumRounds is the number of ZKBoo repetitions for soundness.
// 136 rounds gives a soundness error of (2/3)^136 ≈ 2^{-79}.
const NumRounds = 136

// Prove generates a ZKBoo proof that the prover knows a witness satisfying
// the R1CS circuit. The witness must include w[0]=1 and all public/private signals.
func Prove(circuit *R1CSCircuit, witness *Witness) (*CircomProof, error) {
	if uint32(len(witness.Values)) != circuit.NWires {
		return nil, fmt.Errorf("witness size %d does not match circuit wires %d",
			len(witness.Values), circuit.NWires)
	}

	// Verify w[0] = 1
	if !witness.Values[0].Equal(One()) {
		return nil, fmt.Errorf("witness[0] must be 1, got %s", witness.Values[0])
	}

	// Pre-check: verify the witness actually satisfies the constraints
	if err := checkWitness(circuit, witness); err != nil {
		return nil, fmt.Errorf("invalid witness: %w", err)
	}

	// Phase 1: Generate all round commitments
	type roundState struct {
		keys   [3][16]byte
		salts  [3][4]byte
		shares [3][]FieldElement
		views  [3]ArithView
		commit ArithCommitment
	}
	rounds := make([]roundState, NumRounds)

	for r := 0; r < NumRounds; r++ {
		// Generate per-party keys and salts
		for i := 0; i < 3; i++ {
			rand.Read(rounds[r].keys[i][:])
			rand.Read(rounds[r].salts[i][:])
		}

		// Secret-share the witness
		shares, err := shareWitness(witness.Values)
		if err != nil {
			return nil, fmt.Errorf("round %d: share witness: %w", r, err)
		}
		rounds[r].shares = shares

		// Expand randomness for each party
		randSize := randomnessSizeForCircuit(circuit.NConstraints)
		var randomness [3][]byte
		for i := 0; i < 3; i++ {
			randomness[i], err = expandRandomness(rounds[r].keys[i], randSize)
			if err != nil {
				return nil, fmt.Errorf("round %d: expand randomness: %w", r, err)
			}
		}

		// Execute the MPC circuit
		views, err := executeMPC(circuit, shares, randomness)
		if err != nil {
			return nil, fmt.Errorf("round %d: execute MPC: %w", r, err)
		}
		rounds[r].views = views

		// Extract public output shares (wires 1..NPubOut)
		var outputShares [3][]FieldElement
		for i := 0; i < 3; i++ {
			outputShares[i] = make([]FieldElement, circuit.NPubOut)
			for j := uint32(0); j < circuit.NPubOut; j++ {
				outputShares[i][j] = shares[i][1+j]
			}
		}

		// Commit each party's view
		var hashes [3][32]byte
		for i := 0; i < 3; i++ {
			hashes[i] = commitArithView(rounds[r].keys[i], views[i], rounds[r].salts[i])
		}

		rounds[r].commit = ArithCommitment{
			OutputShares: outputShares,
			Hashes:       hashes,
		}
	}

	// Phase 2: Generate challenges (Fiat-Shamir)
	commitments := make([]ArithCommitment, NumRounds)
	for r := 0; r < NumRounds; r++ {
		commitments[r] = rounds[r].commit
	}
	challenges := arithH3Multi(commitments)

	// Phase 3: Generate responses
	responses := make([]ArithResponse, NumRounds)
	for r := 0; r < NumRounds; r++ {
		e := challenges[r]
		e1 := (e + 1) % 3
		responses[r] = ArithResponse{
			E:     e,
			Key0:  rounds[r].keys[e],
			Key1:  rounds[r].keys[e1],
			View0: rounds[r].views[e],
			View1: rounds[r].views[e1],
			Rand0: rounds[r].salts[e],
			Rand1: rounds[r].salts[e1],
		}
	}

	return &CircomProof{
		NumRounds:   NumRounds,
		NWires:      circuit.NWires,
		NPubOut:     circuit.NPubOut,
		Commitments: commitments,
		Responses:   responses,
	}, nil
}

// executeMPC runs the 3-party MPC simulation of the R1CS circuit.
// For each constraint <A,w>*<B,w> = <C,w>, it:
//  1. Evaluates the A and B linear combinations on each party's share (free)
//  2. Performs a 3-party secure multiplication (uses randomness)
//  3. Records the multiplication output in each party's view
func executeMPC(circuit *R1CSCircuit, shares [3][]FieldElement, randomness [3][]byte) ([3]ArithView, error) {
	nConstraints := int(circuit.NConstraints)
	var views [3]ArithView
	for i := 0; i < 3; i++ {
		views[i] = ArithView{
			InputShare: shares[i],
			MulOutputs: make([]FieldElement, nConstraints),
		}
	}

	randOffset := 0
	for c := 0; c < nConstraints; c++ {
		constraint := &circuit.Constraints[c]

		// Evaluate A and B linear combinations for each party (linear = free)
		var a, b [3]FieldElement
		for i := 0; i < 3; i++ {
			a[i] = evalLinearCombination(constraint.A, shares[i])
			b[i] = evalLinearCombination(constraint.B, shares[i])
		}

		// Secure multiplication: z = a * b
		z := mpcMul3(a, b, randomness, &randOffset)

		// Record outputs
		for i := 0; i < 3; i++ {
			views[i].MulOutputs[c] = z[i]
		}
	}

	return views, nil
}

// checkWitness verifies that the witness satisfies all R1CS constraints.
func checkWitness(circuit *R1CSCircuit, witness *Witness) error {
	for i, c := range circuit.Constraints {
		a := evalLinearCombinationFull(c.A, witness.Values)
		b := evalLinearCombinationFull(c.B, witness.Values)
		cVal := evalLinearCombinationFull(c.C, witness.Values)
		if !a.Mul(b).Equal(cVal) {
			return fmt.Errorf("constraint %d not satisfied: %s * %s != %s", i, a, b, cVal)
		}
	}
	return nil
}

// evalLinearCombinationFull evaluates a linear combination on the full witness.
func evalLinearCombinationFull(lc []Term, witness []FieldElement) FieldElement {
	result := Zero()
	for _, term := range lc {
		result = result.Add(term.Coefficient.Mul(witness[term.WireID]))
	}
	return result
}
