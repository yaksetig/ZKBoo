// RangeProof: Prove that a private input x lies in [0, 2^n) by
// decomposing it into n bits and verifying each bit is 0 or 1.
//
// Usage:
//   circom range_proof.circom --r1cs --wasm --sym
//   cd range_proof_js && node generate_witness.js range_proof.wasm ../range_input.json ../witness.wtns
//   zkboo circom -r1cs range_proof.r1cs -wtns witness.wtns -verify

pragma circom 2.0.0;

template Num2Bits(n) {
    signal input in;
    signal output out[n];

    var lc = 0;
    var bit_value = 1;

    for (var i = 0; i < n; i++) {
        out[i] <-- (in >> i) & 1;
        out[i] * (out[i] - 1) === 0;  // each bit is 0 or 1
        lc += out[i] * bit_value;
        bit_value = bit_value * 2;
    }

    lc === in;  // bits reconstruct to the original value
}

template RangeProof(n) {
    signal input x;
    signal output out;

    component bits = Num2Bits(n);
    bits.in <== x;

    // Output 1 if the proof is valid (always true for a satisfied circuit)
    out <== 1;
}

// Prove x is in [0, 2^8) i.e. x is a valid unsigned 8-bit integer
component main = RangeProof(8);
