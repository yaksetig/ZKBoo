package circom

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
)

// JSON-serializable proof structures

type jsonFieldElement struct {
	Hex string `json:"hex"`
}

type jsonArithView struct {
	InputShare []jsonFieldElement `json:"input_share"`
	MulOutputs []jsonFieldElement `json:"mul_outputs"`
}

type jsonArithCommitment struct {
	OutputShares [3][]jsonFieldElement `json:"output_shares"`
	Hashes       [3]string            `json:"hashes"`
}

type jsonArithResponse struct {
	E     int           `json:"e"`
	Key0  string        `json:"key0"`
	Key1  string        `json:"key1"`
	View0 jsonArithView `json:"view0"`
	View1 jsonArithView `json:"view1"`
	Rand0 string        `json:"rand0"`
	Rand1 string        `json:"rand1"`
}

type jsonCircomProof struct {
	NumRounds    int                   `json:"num_rounds"`
	NWires       uint32                `json:"n_wires"`
	NPubOut      uint32                `json:"n_pub_out"`
	PubOutputs   []jsonFieldElement    `json:"public_outputs"`
	Commitments  []jsonArithCommitment `json:"commitments"`
	Responses    []jsonArithResponse   `json:"responses"`
}

func feToJSON(fe FieldElement) jsonFieldElement {
	b := fe.Bytes()
	return jsonFieldElement{Hex: hex.EncodeToString(b[:])}
}

func feFromJSON(j jsonFieldElement) (FieldElement, error) {
	b, err := hex.DecodeString(j.Hex)
	if err != nil {
		return Zero(), fmt.Errorf("decode hex: %w", err)
	}
	return FieldElementFromBytes(b), nil
}

func feSliceToJSON(fes []FieldElement) []jsonFieldElement {
	out := make([]jsonFieldElement, len(fes))
	for i, fe := range fes {
		out[i] = feToJSON(fe)
	}
	return out
}

func feSliceFromJSON(js []jsonFieldElement) ([]FieldElement, error) {
	out := make([]FieldElement, len(js))
	for i, j := range js {
		fe, err := feFromJSON(j)
		if err != nil {
			return nil, fmt.Errorf("element %d: %w", i, err)
		}
		out[i] = fe
	}
	return out, nil
}

// SaveProof writes a proof to a JSON file along with the public outputs.
func SaveProof(path string, proof *CircomProof, publicOutputs []FieldElement) error {
	jp := jsonCircomProof{
		NumRounds:  proof.NumRounds,
		NWires:     proof.NWires,
		NPubOut:    proof.NPubOut,
		PubOutputs: feSliceToJSON(publicOutputs),
	}

	jp.Commitments = make([]jsonArithCommitment, len(proof.Commitments))
	for i, c := range proof.Commitments {
		var jc jsonArithCommitment
		for p := 0; p < 3; p++ {
			jc.OutputShares[p] = feSliceToJSON(c.OutputShares[p])
			jc.Hashes[p] = hex.EncodeToString(c.Hashes[p][:])
		}
		jp.Commitments[i] = jc
	}

	jp.Responses = make([]jsonArithResponse, len(proof.Responses))
	for i, r := range proof.Responses {
		jp.Responses[i] = jsonArithResponse{
			E:    r.E,
			Key0: hex.EncodeToString(r.Key0[:]),
			Key1: hex.EncodeToString(r.Key1[:]),
			View0: jsonArithView{
				InputShare: feSliceToJSON(r.View0.InputShare),
				MulOutputs: feSliceToJSON(r.View0.MulOutputs),
			},
			View1: jsonArithView{
				InputShare: feSliceToJSON(r.View1.InputShare),
				MulOutputs: feSliceToJSON(r.View1.MulOutputs),
			},
			Rand0: hex.EncodeToString(r.Rand0[:]),
			Rand1: hex.EncodeToString(r.Rand1[:]),
		}
	}

	data, err := json.MarshalIndent(jp, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	return os.WriteFile(path, data, 0644)
}

// LoadProof reads a proof from a JSON file.
func LoadProof(path string) (*CircomProof, []FieldElement, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("read file: %w", err)
	}

	var jp jsonCircomProof
	if err := json.Unmarshal(data, &jp); err != nil {
		return nil, nil, fmt.Errorf("unmarshal: %w", err)
	}

	pubOutputs, err := feSliceFromJSON(jp.PubOutputs)
	if err != nil {
		return nil, nil, fmt.Errorf("parse public outputs: %w", err)
	}

	proof := &CircomProof{
		NumRounds: jp.NumRounds,
		NWires:    jp.NWires,
		NPubOut:   jp.NPubOut,
	}

	proof.Commitments = make([]ArithCommitment, len(jp.Commitments))
	for i, jc := range jp.Commitments {
		var c ArithCommitment
		for p := 0; p < 3; p++ {
			c.OutputShares[p], err = feSliceFromJSON(jc.OutputShares[p])
			if err != nil {
				return nil, nil, fmt.Errorf("commitment %d, party %d: %w", i, p, err)
			}
			hashBytes, err := hex.DecodeString(jc.Hashes[p])
			if err != nil {
				return nil, nil, fmt.Errorf("commitment %d hash %d: %w", i, p, err)
			}
			copy(c.Hashes[p][:], hashBytes)
		}
		proof.Commitments[i] = c
	}

	proof.Responses = make([]ArithResponse, len(jp.Responses))
	for i, jr := range jp.Responses {
		var r ArithResponse
		r.E = jr.E
		k0, err := hex.DecodeString(jr.Key0)
		if err != nil {
			return nil, nil, fmt.Errorf("response %d key0: %w", i, err)
		}
		copy(r.Key0[:], k0)
		k1, err := hex.DecodeString(jr.Key1)
		if err != nil {
			return nil, nil, fmt.Errorf("response %d key1: %w", i, err)
		}
		copy(r.Key1[:], k1)

		r.View0.InputShare, err = feSliceFromJSON(jr.View0.InputShare)
		if err != nil {
			return nil, nil, fmt.Errorf("response %d view0 input: %w", i, err)
		}
		r.View0.MulOutputs, err = feSliceFromJSON(jr.View0.MulOutputs)
		if err != nil {
			return nil, nil, fmt.Errorf("response %d view0 outputs: %w", i, err)
		}
		r.View1.InputShare, err = feSliceFromJSON(jr.View1.InputShare)
		if err != nil {
			return nil, nil, fmt.Errorf("response %d view1 input: %w", i, err)
		}
		r.View1.MulOutputs, err = feSliceFromJSON(jr.View1.MulOutputs)
		if err != nil {
			return nil, nil, fmt.Errorf("response %d view1 outputs: %w", i, err)
		}

		r0, err := hex.DecodeString(jr.Rand0)
		if err != nil {
			return nil, nil, fmt.Errorf("response %d rand0: %w", i, err)
		}
		copy(r.Rand0[:], r0)
		r1, err := hex.DecodeString(jr.Rand1)
		if err != nil {
			return nil, nil, fmt.Errorf("response %d rand1: %w", i, err)
		}
		copy(r.Rand1[:], r1)

		proof.Responses[i] = r
	}

	return proof, pubOutputs, nil
}
