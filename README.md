# ZKBoo

Zero Knowledge Prover and Verifier using the MPC-in-the-head paradigm.

Supports two modes:
- **Boolean circuits** — built-in provers/verifiers for SHA-1 and SHA-256
- **Circom R1CS circuits** — prove any [Circom](https://docs.circom.io/)-compiled circuit using arithmetic MPC-in-the-head over the BN254 scalar field

## Quick Start (Go CLI)

```bash
go build -o zkboo ./cmd/zkboo/

# SHA-256 proof
./zkboo -algo sha256 -msg "hello" -out proof.json -verify

# Circom circuit proof (see below)
./zkboo circom -r1cs circuit.r1cs -wtns witness.wtns -out proof.json -verify
```

## Circom Integration

The `circom` subpackage extends ZKBoo from boolean circuits to arithmetic circuits over the BN254 scalar field. This lets you write a circuit in [Circom](https://docs.circom.io/), compile it to R1CS, and generate a ZKBoo proof — no trusted setup required.

### How It Works

Each R1CS constraint `<A,w> * <B,w> = <C,w>` maps to exactly one arithmetic MPC multiplication gate:

1. **Linear combinations** (the A, B, C dot products) are free — each party computes them locally on their additive share
2. **Multiplication** uses the ZKBoo 3-party protocol lifted from GF(2) to F_p:
   `z[i] = x[i]*y[next] + x[next]*y[i] + x[i]*y[i] + r[i] - r[next]`
3. **136 rounds** of commit-challenge-reveal give soundness error (2/3)^136 ≈ 2^{-79}

### End-to-End Example

Here's a complete walkthrough using the included `multiplier.circom` example:

**1. Write a Circom circuit** (see [`examples/circom/multiplier.circom`](examples/circom/multiplier.circom)):

```circom
pragma circom 2.0.0;

template Multiplier2() {
    signal input a;
    signal input b;
    signal output c;

    c <== a * b;
}

component main = Multiplier2();
```

**2. Compile with Circom** (requires [circom](https://docs.circom.io/getting-started/installation/) installed):

```bash
circom examples/circom/multiplier.circom --r1cs --wasm --sym -o examples/circom/
```

**3. Generate the witness** (requires Node.js):

```bash
cd examples/circom/multiplier_js
node generate_witness.js multiplier.wasm ../input.json ../witness.wtns
cd ../../..
```

**4. Generate and verify the ZKBoo proof:**

```bash
./zkboo circom \
  -r1cs examples/circom/multiplier.r1cs \
  -wtns examples/circom/witness.wtns \
  -out multiplier_proof.json \
  -verify
```

**5. Verify an existing proof** (without the witness):

```bash
./zkboo circom \
  -r1cs examples/circom/multiplier.r1cs \
  -verify-proof multiplier_proof.json
```

### More Examples

- **`examples/circom/multiplier.circom`** — Prove knowledge of `a * b = c` (1 constraint)
- **`examples/circom/range_proof.circom`** — Prove a value is in [0, 2^8) via bit decomposition (9 constraints)

### Programmatic Usage

```go
import "zkboo/circom"

// Parse Circom outputs
circuit, _ := circom.ParseR1CS("circuit.r1cs")
witness, _ := circom.ParseWitness("witness.wtns")

// Generate proof
proof, _ := circom.Prove(circuit, witness)

// Extract public outputs (wires 1..NPubOut)
pubOutputs := witness.Values[1 : 1+circuit.NPubOut]

// Verify
ok, _ := circom.Verify(circuit, proof, pubOutputs)

// Serialize
circom.SaveProof("proof.json", proof, pubOutputs)
```

### Architecture

```
circom/
├── field.go       BN254 scalar field arithmetic (add, sub, mul, neg)
├── r1cs.go        Parser for Circom's .r1cs binary format
├── witness.go     Parser for Circom's .wtns binary format
├── mpc.go         Arithmetic MPC gates (3-party field multiplication)
├── prover.go      136-round arithmetic ZKBoo prover
├── verifier.go    Verifier with Fiat-Shamir challenges
├── serialize.go   JSON proof serialization
└── types.go       Shared types (R1CSCircuit, ArithView, CircomProof)
```

### Properties

| Property | Value |
|---|---|
| Proof system | ZKBoo (MPC-in-the-head) |
| Field | BN254 scalar field (≈254-bit prime) |
| Trusted setup | **None** |
| Soundness | (2/3)^136 ≈ 2^{-79} |
| Post-quantum | Yes (symmetric-crypto based) |
| Cost per constraint | 1 multiplication gate + 32 bytes randomness/party |

## Boolean Circuits (SHA-1/SHA-256)

The original ZKBoo implementation for SHA hash preimage proofs. Uses boolean MPC gates (XOR, AND) with the C implementation relying on OpenSSL for commitments and OpenMP for parallelization.

When starting either prover, it will prompt for an input to hash. After entering the input, the proof will be generated as a file in the directory the program resides in. The file is named out<NUM_ROUNDS>.bin where <NUM_ROUNDS> is the number of rounds of the algorithm run (set to 136 by default, but can be changed in shared.h). Likewise, the verifier will look for a file in its directory with the same naming syntax to verify.

## References

- [ZKBoo: Faster Zero-Knowledge for Boolean Circuits](https://eprint.iacr.org/2016/163.pdf)
- [ZKB++](https://eprint.iacr.org/2017/279.pdf) — improved version with NIZK proofs less than half the size
- [Circom Documentation](https://docs.circom.io/)
- [KKW (Katz-Kolesnikov-Wang)](https://eprint.iacr.org/2018/475.pdf) — arithmetic MPC-in-the-head construction
