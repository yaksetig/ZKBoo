// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SHA256Verifier {
    uint constant Y_SIZE = 736;
    uint constant RANDOMNESS_SIZE = 2912;

    uint32[8] constant H_INIT = [
        uint32(0x6a09e667),
        uint32(0xbb67ae85),
        uint32(0x3c6ef372),
        uint32(0xa54ff53a),
        uint32(0x510e527f),
        uint32(0x9b05688c),
        uint32(0x1f83d9ab),
        uint32(0x5be0cd19)
    ];

    uint32[64] constant K = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98,
        0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6,
        0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3,
        0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138,
        0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e,
        0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
        0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814,
        0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ];

    struct View {
        uint8[64] X;
        uint32[Y_SIZE] Y;
    }

    struct A {
        uint32[8][3] Yp;
        bytes32[3] H;
    }

    struct Z {
        bytes16 Ke;
        bytes16 Ke1;
        View Ve;
        View Ve1;
        bytes4 Re;
        bytes4 Re1;
    }

    function rightRotate(uint32 x, uint n) internal pure returns (uint32) {
        return (x >> n) | (x << (32 - n));
    }

    function mpcXOR2(uint32[2] memory x, uint32[2] memory y) internal pure returns (uint32[2] memory z) {
        z[0] = x[0] ^ y[0];
        z[1] = x[1] ^ y[1];
    }

    function mpcRIGHTROTATE2(uint32[2] memory x, uint n) internal pure returns (uint32[2] memory z) {
        z[0] = rightRotate(x[0], n);
        z[1] = rightRotate(x[1], n);
    }

    function mpcRIGHTSHIFT2(uint32[2] memory x, uint n) internal pure returns (uint32[2] memory z) {
        z[0] = x[0] >> n;
        z[1] = x[1] >> n;
    }

    function getRandom32(bytes memory randomness, uint offset) internal pure returns (uint32) {
        return uint32(uint8(randomness[offset])) |
            (uint32(uint8(randomness[offset + 1])) << 8) |
            (uint32(uint8(randomness[offset + 2])) << 16) |
            (uint32(uint8(randomness[offset + 3])) << 24);
    }

    function getBit(uint32 x, uint i) internal pure returns (uint32) {
        return (x >> i) & 1;
    }

    function computeH(bytes16 k, View memory v, bytes4 r) internal pure returns (bytes32) {
        bytes memory data = new bytes(16 + 64 + 4 * Y_SIZE + 4);
        uint ptr = 0;
        for (uint i = 0; i < 16; i++) data[ptr++] = k[i];
        for (uint i = 0; i < 64; i++) data[ptr++] = bytes1(v.X[i]);
        for (uint i = 0; i < Y_SIZE; i++) {
            uint32 y = v.Y[i];
            data[ptr++] = bytes1(uint8(y));
            data[ptr++] = bytes1(uint8(y >> 8));
            data[ptr++] = bytes1(uint8(y >> 16));
            data[ptr++] = bytes1(uint8(y >> 24));
        }
        for (uint i = 0; i < 4; i++) data[ptr++] = r[i];
        return sha256(data);
    }

    function outputSHA256(View memory v) internal pure returns (uint32[8] memory res) {
        for (uint i = 0; i < 8; i++) {
            res[i] = v.Y[Y_SIZE - 8 + i];
        }
    }

    function getAllRandomness(bytes16 key) internal pure returns (bytes memory out) {
        out = new bytes(RANDOMNESS_SIZE);
        uint offset = 0;
        uint counter = 0;
        while (offset < RANDOMNESS_SIZE) {
            bytes32 block = sha256(abi.encodePacked(key, counter));
            for (uint i = 0; i < 32 && offset < RANDOMNESS_SIZE; i++) {
                out[offset++] = block[i];
            }
            counter++;
        }
    }

    function mpcANDVerify(
        uint32[2] memory x,
        uint32[2] memory y,
        View memory ve,
        View memory ve1,
        bytes memory rand0,
        bytes memory rand1,
        uint randCount,
        uint countY
    ) internal pure returns (bool, uint32[2] memory, uint, uint) {
        uint32 r0 = getRandom32(rand0, randCount);
        uint32 r1 = getRandom32(rand1, randCount);
        randCount += 4;
        uint32 t = (x[0] & y[1]) ^ (x[1] & y[0]) ^ (x[0] & y[0]) ^ r0 ^ r1;
        if (ve.Y[countY] != t) {
            return (false, x, randCount, countY);
        }
        uint32[2] memory z;
        z[0] = t;
        z[1] = ve1.Y[countY];
        countY += 1;
        return (true, z, randCount, countY);
    }

    function mpcADDVerify(
        uint32[2] memory x,
        uint32[2] memory y,
        View memory ve,
        View memory ve1,
        bytes memory rand0,
        bytes memory rand1,
        uint randCount,
        uint countY
    ) internal pure returns (bool, uint32[2] memory, uint, uint) {
        uint32 r0 = getRandom32(rand0, randCount);
        uint32 r1 = getRandom32(rand1, randCount);
        randCount += 4;
        for (uint i = 0; i < 31; i++) {
            uint32 a0 = getBit(x[0] ^ ve.Y[countY], i);
            uint32 a1 = getBit(x[1] ^ ve1.Y[countY], i);
            uint32 b0 = getBit(y[0] ^ ve.Y[countY], i);
            uint32 b1 = getBit(y[1] ^ ve1.Y[countY], i);
            uint32 t = (a0 & b1) ^ (a1 & b0) ^ getBit(r1, i);
            if (getBit(ve.Y[countY], i + 1) != (t ^ (a0 & b0) ^ getBit(ve.Y[countY], i) ^ getBit(r0, i))) {
                return (false, x, randCount, countY);
            }
        }
        uint32[2] memory z;
        z[0] = x[0] ^ y[0] ^ ve.Y[countY];
        z[1] = x[1] ^ y[1] ^ ve1.Y[countY];
        countY += 1;
        return (true, z, randCount, countY);
    }

    function mpcMAJVerify(
        uint32[2] memory a,
        uint32[2] memory b,
        uint32[2] memory c,
        View memory ve,
        View memory ve1,
        bytes memory rand0,
        bytes memory rand1,
        uint randCount,
        uint countY
    ) internal pure returns (bool, uint32[2] memory, uint, uint) {
        uint32[2] memory t0 = mpcXOR2(a, b);
        uint32[2] memory t1 = mpcXOR2(a, c);
        bool ok;
        (ok, t0, randCount, countY) = mpcANDVerify(t0, t1, ve, ve1, rand0, rand1, randCount, countY);
        if (!ok) return (false, t0, randCount, countY);
        uint32[2] memory maj = mpcXOR2(t0, a);
        return (true, maj, randCount, countY);
    }

    function mpcCHVerify(
        uint32[2] memory e,
        uint32[2] memory f,
        uint32[2] memory g,
        View memory ve,
        View memory ve1,
        bytes memory rand0,
        bytes memory rand1,
        uint randCount,
        uint countY
    ) internal pure returns (bool, uint32[2] memory, uint, uint) {
        uint32[2] memory t0 = mpcXOR2(f, g);
        bool ok;
        (ok, t0, randCount, countY) = mpcANDVerify(e, t0, ve, ve1, rand0, rand1, randCount, countY);
        if (!ok) return (false, t0, randCount, countY);
        uint32[2] memory ch = mpcXOR2(t0, g);
        return (true, ch, randCount, countY);
    }

    function pair(uint32 x) internal pure returns (uint32[2] memory p) {
        p[0] = x;
        p[1] = x;
    }

    function verify(A memory a, uint8 e, Z memory z) public pure returns (bool) {
        if (computeH(z.Ke, z.Ve, z.Re) != a.H[e]) return false;
        if (computeH(z.Ke1, z.Ve1, z.Re1) != a.H[(e + 1) % 3]) return false;

        uint32[8] memory res = outputSHA256(z.Ve);
        for (uint i = 0; i < 8; i++) {
            if (a.Yp[e][i] != res[i]) return false;
        }
        res = outputSHA256(z.Ve1);
        for (uint i = 0; i < 8; i++) {
            if (a.Yp[(e + 1) % 3][i] != res[i]) return false;
        }

        bytes memory rand0 = getAllRandomness(z.Ke);
        bytes memory rand1 = getAllRandomness(z.Ke1);
        uint randCount = 0;
        uint countY = 0;

        uint32[2][64] memory w;
        for (uint j = 0; j < 16; j++) {
            w[j][0] = (uint32(z.Ve.X[j * 4]) << 24) |
                (uint32(z.Ve.X[j * 4 + 1]) << 16) |
                (uint32(z.Ve.X[j * 4 + 2]) << 8) |
                uint32(z.Ve.X[j * 4 + 3]);
            w[j][1] = (uint32(z.Ve1.X[j * 4]) << 24) |
                (uint32(z.Ve1.X[j * 4 + 1]) << 16) |
                (uint32(z.Ve1.X[j * 4 + 2]) << 8) |
                uint32(z.Ve1.X[j * 4 + 3]);
        }
        uint32[2] memory s0;
        uint32[2] memory s1;
        uint32[2] memory t0;
        uint32[2] memory t1;
        bool ok;
        for (uint j = 16; j < 64; j++) {
            t0 = mpcRIGHTROTATE2(w[j - 15], 7);
            t1 = mpcRIGHTROTATE2(w[j - 15], 18);
            t0 = mpcXOR2(t0, t1);
            t1 = mpcRIGHTSHIFT2(w[j - 15], 3);
            s0 = mpcXOR2(t0, t1);

            t0 = mpcRIGHTROTATE2(w[j - 2], 17);
            t1 = mpcRIGHTROTATE2(w[j - 2], 19);
            t0 = mpcXOR2(t0, t1);
            t1 = mpcRIGHTSHIFT2(w[j - 2], 10);
            s1 = mpcXOR2(t0, t1);

            (ok, t1, randCount, countY) = mpcADDVerify(w[j - 16], s0, z.Ve, z.Ve1, rand0, rand1, randCount, countY);
            if (!ok) return false;
            (ok, t1, randCount, countY) = mpcADDVerify(w[j - 7], t1, z.Ve, z.Ve1, rand0, rand1, randCount, countY);
            if (!ok) return false;
            (ok, w[j], randCount, countY) = mpcADDVerify(t1, s1, z.Ve, z.Ve1, rand0, rand1, randCount, countY);
            if (!ok) return false;
        }

        uint32[2] memory va = pair(H_INIT[0]);
        uint32[2] memory vb = pair(H_INIT[1]);
        uint32[2] memory vc = pair(H_INIT[2]);
        uint32[2] memory vd = pair(H_INIT[3]);
        uint32[2] memory ve2 = pair(H_INIT[4]);
        uint32[2] memory vf = pair(H_INIT[5]);
        uint32[2] memory vg = pair(H_INIT[6]);
        uint32[2] memory vh = pair(H_INIT[7]);
        uint32[2] memory temp1;
        uint32[2] memory temp2;
        uint32[2] memory maj;
        for (uint i = 0; i < 64; i++) {
            t0 = mpcRIGHTROTATE2(ve2, 6);
            t1 = mpcRIGHTROTATE2(ve2, 11);
            t0 = mpcXOR2(t0, t1);
            t1 = mpcRIGHTROTATE2(ve2, 25);
            s1 = mpcXOR2(t0, t1);

            (ok, t0, randCount, countY) = mpcADDVerify(vh, s1, z.Ve, z.Ve1, rand0, rand1, randCount, countY);
            if (!ok) return false;
            (ok, t1, randCount, countY) = mpcCHVerify(ve2, vf, vg, z.Ve, z.Ve1, rand0, rand1, randCount, countY);
            if (!ok) return false;
            (ok, t1, randCount, countY) = mpcADDVerify(t0, t1, z.Ve, z.Ve1, rand0, rand1, randCount, countY);
            if (!ok) return false;
            (ok, t1, randCount, countY) = mpcADDVerify(t1, pair(K[i]), z.Ve, z.Ve1, rand0, rand1, randCount, countY);
            if (!ok) return false;
            (ok, temp1, randCount, countY) = mpcADDVerify(t1, w[i], z.Ve, z.Ve1, rand0, rand1, randCount, countY);
            if (!ok) return false;

            t0 = mpcRIGHTROTATE2(va, 2);
            t1 = mpcRIGHTROTATE2(va, 13);
            t0 = mpcXOR2(t0, t1);
            t1 = mpcRIGHTROTATE2(va, 22);
            s0 = mpcXOR2(t0, t1);

            (ok, maj, randCount, countY) = mpcMAJVerify(va, vb, vc, z.Ve, z.Ve1, rand0, rand1, randCount, countY);
            if (!ok) return false;
            (ok, temp2, randCount, countY) = mpcADDVerify(s0, maj, z.Ve, z.Ve1, rand0, rand1, randCount, countY);
            if (!ok) return false;

            vh = vg;
            vg = vf;
            vf = ve2;
            (ok, ve2, randCount, countY) = mpcADDVerify(vd, temp1, z.Ve, z.Ve1, rand0, rand1, randCount, countY);
            if (!ok) return false;
            vd = vc;
            vc = vb;
            vb = va;
            (ok, va, randCount, countY) = mpcADDVerify(temp1, temp2, z.Ve, z.Ve1, rand0, rand1, randCount, countY);
            if (!ok) return false;
        }

        (ok, temp1, randCount, countY) = mpcADDVerify(pair(H_INIT[0]), va, z.Ve, z.Ve1, rand0, rand1, randCount, countY);
        if (!ok) return false;
        (ok, temp1, randCount, countY) = mpcADDVerify(pair(H_INIT[1]), vb, z.Ve, z.Ve1, rand0, rand1, randCount, countY);
        if (!ok) return false;
        (ok, temp1, randCount, countY) = mpcADDVerify(pair(H_INIT[2]), vc, z.Ve, z.Ve1, rand0, rand1, randCount, countY);
        if (!ok) return false;
        (ok, temp1, randCount, countY) = mpcADDVerify(pair(H_INIT[3]), vd, z.Ve, z.Ve1, rand0, rand1, randCount, countY);
        if (!ok) return false;
        (ok, temp1, randCount, countY) = mpcADDVerify(pair(H_INIT[4]), ve2, z.Ve, z.Ve1, rand0, rand1, randCount, countY);
        if (!ok) return false;
        (ok, temp1, randCount, countY) = mpcADDVerify(pair(H_INIT[5]), vf, z.Ve, z.Ve1, rand0, rand1, randCount, countY);
        if (!ok) return false;
        (ok, temp1, randCount, countY) = mpcADDVerify(pair(H_INIT[6]), vg, z.Ve, z.Ve1, rand0, rand1, randCount, countY);
        if (!ok) return false;
        (ok, temp1, randCount, countY) = mpcADDVerify(pair(H_INIT[7]), vh, z.Ve, z.Ve1, rand0, rand1, randCount, countY);
        if (!ok) return false;

        return true;
    }
}

