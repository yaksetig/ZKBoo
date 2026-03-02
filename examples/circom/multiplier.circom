// Multiplier2: Prove knowledge of two private inputs a, b
// such that a * b equals the public output.
//
// Usage:
//   circom multiplier.circom --r1cs --wasm --sym
//   cd multiplier_js && node generate_witness.js multiplier.wasm ../input.json ../witness.wtns
//   zkboo circom -r1cs multiplier.r1cs -wtns witness.wtns -verify

pragma circom 2.0.0;

template Multiplier2() {
    signal input a;
    signal input b;
    signal output c;

    c <== a * b;
}

component main = Multiplier2();
