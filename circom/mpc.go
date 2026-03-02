package circom

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
)

// getFieldRandomnessAt reads one field element worth of randomness (32 bytes)
// from the randomness tape at the given offset (does not advance offset).
func getFieldRandomnessAt(randomness []byte, offset int) FieldElement {
	return FieldElementFromBytes(randomness[offset : offset+FieldSize])
}

// expandRandomness uses AES-CTR to expand a 16-byte key into pseudorandom bytes.
func expandRandomness(key [16]byte, length int) ([]byte, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	iv := []byte("0123456789012345")
	stream := cipher.NewCTR(block, iv)
	out := make([]byte, length)
	zeros := make([]byte, length)
	stream.XORKeyStream(out, zeros)
	return out, nil
}

// evalLinearCombination computes the dot product <lc, witnessShare> for one party.
// This is a linear operation and is "free" in the MPC — no randomness needed.
func evalLinearCombination(lc []Term, witnessShare []FieldElement) FieldElement {
	result := Zero()
	for _, term := range lc {
		result = result.Add(term.Coefficient.Mul(witnessShare[term.WireID]))
	}
	return result
}

// mpcMul3 performs a 3-party secure multiplication of shared values.
//
// Given shares [x0, x1, x2] of x and [y0, y1, y2] of y (where x = x0+x1+x2
// and y = y0+y1+y2 mod p), it computes shares [z0, z1, z2] of z = x*y.
//
// The formula (analogous to Boolean AND in ZKBoo):
//
//	z[i] = x[i]*y[(i+1)%3] + x[(i+1)%3]*y[i] + x[i]*y[i] + r[i] - r[(i+1)%3]
//
// where r[0], r[1], r[2] are random field elements.
// This ensures z[0] + z[1] + z[2] = (x[0]+x[1]+x[2]) * (y[0]+y[1]+y[2]) mod p.
func mpcMul3(x, y [3]FieldElement, randomness [3][]byte, randOffset *int) [3]FieldElement {
	r := [3]FieldElement{
		getFieldRandomnessAt(randomness[0], *randOffset),
		getFieldRandomnessAt(randomness[1], *randOffset),
		getFieldRandomnessAt(randomness[2], *randOffset),
	}
	*randOffset += FieldSize

	var z [3]FieldElement
	for i := 0; i < 3; i++ {
		next := (i + 1) % 3
		// z[i] = x[i]*y[next] + x[next]*y[i] + x[i]*y[i] + r[i] - r[next]
		z[i] = x[i].Mul(y[next]).Add(x[next].Mul(y[i])).Add(x[i].Mul(y[i])).Add(r[i]).Sub(r[next])
	}
	return z
}

// mpcMul2Verify recomputes party e's multiplication output given parties e and e+1.
// Returns the computed z[e] and the assumed z[e+1] (from the view).
//
// The verifier knows x[e], y[e], x[e+1], y[e+1], r[e], r[e+1], and view[e+1]'s output.
// It recomputes z[e] and checks consistency.
func mpcMul2Verify(xe, ye, xe1, ye1 FieldElement, randomness [2][]byte, randOffset *int) (FieldElement, FieldElement) {
	re := getFieldRandomnessAt(randomness[0], *randOffset)
	re1 := getFieldRandomnessAt(randomness[1], *randOffset)
	*randOffset += FieldSize

	// z[e] = x[e]*y[e+1] + x[e+1]*y[e] + x[e]*y[e] + r[e] - r[e+1]
	ze := xe.Mul(ye1).Add(xe1.Mul(ye)).Add(xe.Mul(ye)).Add(re).Sub(re1)
	return ze, re1 // re1 used for offset tracking only; ze1 comes from the view
}

// commitArithView creates a SHA-256 commitment of an arithmetic view.
// Format: H(key || inputShare || mulOutputs || salt)
func commitArithView(key [16]byte, view ArithView, salt [4]byte) [32]byte {
	h := sha256.New()
	h.Write(key[:])
	for _, fe := range view.InputShare {
		b := fe.Bytes()
		h.Write(b[:])
	}
	for _, fe := range view.MulOutputs {
		b := fe.Bytes()
		h.Write(b[:])
	}
	h.Write(salt[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// arithH3 generates a challenge e ∈ {0,1,2} from the public outputs and commitments.
// Analogous to h3 in the boolean ZKBoo.
func arithH3(outputShares [3][]FieldElement, hashes [3][32]byte) int {
	h := sha256.New()
	for i := 0; i < 3; i++ {
		for _, fe := range outputShares[i] {
			b := fe.Bytes()
			h.Write(b[:])
		}
	}
	for i := 0; i < 3; i++ {
		h.Write(hashes[i][:])
	}
	hash := h.Sum(nil)
	bitTracker := 0
	for {
		if bitTracker+1 >= len(hash)*8 {
			tmp := sha256.Sum256(hash)
			hash = tmp[:]
			bitTracker = 0
		}
		b1 := (hash[bitTracker/8] >> (bitTracker % 8)) & 1
		b2 := (hash[(bitTracker+1)/8] >> ((bitTracker + 1) % 8)) & 1
		bitTracker += 2
		v := int(b1<<1 | b2)
		if v < 3 {
			return v
		}
	}
}

// arithH3Multi generates a combined challenge for multi-round proofs.
// It hashes all round commitments together to produce per-round challenges.
func arithH3Multi(commitments []ArithCommitment) []int {
	// Hash all commitments together
	master := sha256.New()
	for _, c := range commitments {
		for i := 0; i < 3; i++ {
			for _, fe := range c.OutputShares[i] {
				b := fe.Bytes()
				master.Write(b[:])
			}
		}
		for i := 0; i < 3; i++ {
			master.Write(c.Hashes[i][:])
		}
	}
	seed := master.Sum(nil)

	// Derive per-round challenges from the master hash
	challenges := make([]int, len(commitments))
	hash := seed
	bitTracker := 0
	for i := range challenges {
		for {
			if bitTracker+1 >= len(hash)*8 {
				tmp := sha256.Sum256(hash)
				hash = tmp[:]
				bitTracker = 0
			}
			b1 := (hash[bitTracker/8] >> (bitTracker % 8)) & 1
			b2 := (hash[(bitTracker+1)/8] >> ((bitTracker + 1) % 8)) & 1
			bitTracker += 2
			v := int(b1<<1 | b2)
			if v < 3 {
				challenges[i] = v
				break
			}
		}
	}
	return challenges
}

// randomnessSizeForCircuit returns how many bytes of randomness each party
// needs for the given number of multiplication gates (constraints).
func randomnessSizeForCircuit(nConstraints uint32) int {
	return int(nConstraints) * FieldSize
}

// shareWitness splits a witness into 3 additive shares over F_p.
// w = shares[0] + shares[1] + shares[2] mod p
func shareWitness(w []FieldElement) ([3][]FieldElement, error) {
	n := len(w)
	var shares [3][]FieldElement
	for i := 0; i < 3; i++ {
		shares[i] = make([]FieldElement, n)
	}
	for j := 0; j < n; j++ {
		r0, err := RandomFieldElement()
		if err != nil {
			return shares, err
		}
		r1, err := RandomFieldElement()
		if err != nil {
			return shares, err
		}
		shares[0][j] = r0
		shares[1][j] = r1
		shares[2][j] = w[j].Sub(r0).Sub(r1)
	}
	return shares, nil
}

// reconstructShares reconstructs a value from 3 additive shares.
func reconstructShares(s0, s1, s2 FieldElement) FieldElement {
	return s0.Add(s1).Add(s2)
}

// fieldElementToUint32 extracts the low 32 bits for Fiat-Shamir hashing.
func fieldElementToUint32(fe FieldElement) uint32 {
	b := fe.Bytes()
	return binary.LittleEndian.Uint32(b[:4])
}
