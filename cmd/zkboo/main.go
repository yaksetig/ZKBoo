package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	zk "zkboo"
	"zkboo/circom"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "circom" {
		circomMain(os.Args[2:])
		return
	}

	algo := flag.String("algo", "sha1", "hash algorithm: sha1 or sha256")
	msg := flag.String("msg", "", "message to hash; if empty, read from stdin")
	out := flag.String("out", "proof.json", "path to output proof file")
	verify := flag.Bool("verify", false, "verify the generated proof")
	flag.Parse()

	var input string
	if *msg != "" {
		input = *msg
	} else {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to read stdin: %v\n", err)
			os.Exit(1)
		}
		input = strings.TrimSpace(string(data))
	}

	var (
		proof *zk.Proof
		err   error
	)
	switch strings.ToLower(*algo) {
	case "sha1":
		proof, err = zk.ProveSHA1([]byte(input))
	case "sha256":
		proof, err = zk.ProveSHA256([]byte(input))
	default:
		fmt.Fprintf(os.Stderr, "unknown algorithm %s\n", *algo)
		os.Exit(1)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "proof generation failed: %v\n", err)
		os.Exit(1)
	}

	data, err := json.MarshalIndent(proof, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to marshal proof: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(*out, data, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "failed to write proof: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("proof written to %s\n", *out)

	if *verify {
		var loaded zk.Proof
		data, err := os.ReadFile(*out)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to read proof: %v\n", err)
			os.Exit(1)
		}
		if err := json.Unmarshal(data, &loaded); err != nil {
			fmt.Fprintf(os.Stderr, "failed to parse proof: %v\n", err)
			os.Exit(1)
		}
		var ok bool
		switch strings.ToLower(*algo) {
		case "sha1":
			ok = zk.VerifySHA1([]byte(input), &loaded)
		case "sha256":
			ok = zk.VerifySHA256([]byte(input), &loaded)
		}
		if ok {
			fmt.Println("verification succeeded")
		} else {
			fmt.Println("verification failed")
			os.Exit(1)
		}
	}
}

func circomMain(args []string) {
	fs := flag.NewFlagSet("circom", flag.ExitOnError)
	r1csPath := fs.String("r1cs", "", "path to .r1cs file")
	wtnsPath := fs.String("wtns", "", "path to .wtns witness file")
	outPath := fs.String("out", "circom_proof.json", "path to output proof file")
	verifyFlag := fs.Bool("verify", false, "verify the generated proof")
	verifyOnly := fs.String("verify-proof", "", "path to proof file to verify (skip proving)")
	fs.Parse(args)

	if *verifyOnly != "" {
		// Verify-only mode
		if *r1csPath == "" {
			fmt.Fprintf(os.Stderr, "error: -r1cs is required for verification\n")
			os.Exit(1)
		}
		circuit, err := circom.ParseR1CS(*r1csPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to parse R1CS: %v\n", err)
			os.Exit(1)
		}
		proof, pubOutputs, err := circom.LoadProof(*verifyOnly)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to load proof: %v\n", err)
			os.Exit(1)
		}
		ok, err := circom.Verify(circuit, proof, pubOutputs)
		if err != nil {
			fmt.Fprintf(os.Stderr, "verification error: %v\n", err)
			os.Exit(1)
		}
		if ok {
			fmt.Println("verification succeeded")
		} else {
			fmt.Println("verification failed")
			os.Exit(1)
		}
		return
	}

	// Prove mode
	if *r1csPath == "" || *wtnsPath == "" {
		fmt.Fprintf(os.Stderr, "usage: zkboo circom -r1cs <file.r1cs> -wtns <file.wtns> [-out proof.json] [-verify]\n")
		os.Exit(1)
	}

	fmt.Println("parsing R1CS circuit...")
	circuit, err := circom.ParseR1CS(*r1csPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to parse R1CS: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("  wires: %d, constraints: %d, public outputs: %d, public inputs: %d\n",
		circuit.NWires, circuit.NConstraints, circuit.NPubOut, circuit.NPubIn)

	fmt.Println("parsing witness...")
	witness, err := circom.ParseWitness(*wtnsPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to parse witness: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("  witness values: %d\n", len(witness.Values))

	// Extract public outputs for verification
	publicOutputs := make([]circom.FieldElement, circuit.NPubOut)
	for i := uint32(0); i < circuit.NPubOut; i++ {
		publicOutputs[i] = witness.Values[1+i]
	}

	fmt.Printf("generating ZKBoo proof (%d rounds)...\n", circom.NumRounds)
	proof, err := circom.Prove(circuit, witness)
	if err != nil {
		fmt.Fprintf(os.Stderr, "proof generation failed: %v\n", err)
		os.Exit(1)
	}

	if err := circom.SaveProof(*outPath, proof, publicOutputs); err != nil {
		fmt.Fprintf(os.Stderr, "failed to save proof: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("proof written to %s\n", *outPath)

	if *verifyFlag {
		fmt.Println("verifying proof...")
		ok, err := circom.Verify(circuit, proof, publicOutputs)
		if err != nil {
			fmt.Fprintf(os.Stderr, "verification error: %v\n", err)
			os.Exit(1)
		}
		if ok {
			fmt.Println("verification succeeded")
		} else {
			fmt.Println("verification failed")
			os.Exit(1)
		}
	}
}
