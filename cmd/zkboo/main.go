package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	zk "zkboo"
)

func main() {
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
