package zkboo

func outputSHA256(v View) [8]uint32 {
	var res [8]uint32
	copy(res[:], v.Y[YSizeSHA256-8:YSizeSHA256])
	return res
}

func verifySHA256(a A, e int, z Z) bool {
	hash := computeH(z.Ke, z.Ve, z.Re, YSizeSHA256)
	if a.H[e] != hash {
		return false
	}
	hash = computeH(z.Ke1, z.Ve1, z.Re1, YSizeSHA256)
	if a.H[(e+1)%3] != hash {
		return false
	}
	res := outputSHA256(z.Ve)
	for i := 0; i < 8; i++ {
		if a.Yp[e][i] != res[i] {
			return false
		}
	}
	res = outputSHA256(z.Ve1)
	for i := 0; i < 8; i++ {
		if a.Yp[(e+1)%3][i] != res[i] {
			return false
		}
	}
	var rand0 [RandomnessSizeSHA256]byte
	if err := getAllRandomness(z.Ke, rand0[:]); err != nil {
		return false
	}
	var rand1 [RandomnessSizeSHA256]byte
	if err := getAllRandomness(z.Ke1, rand1[:]); err != nil {
		return false
	}
	randomness := [2][]byte{rand0[:], rand1[:]}
	randCount := 0
	countY := 0
	var w [64][2]uint32
	for j := 0; j < 16; j++ {
		w[j][0] = uint32(z.Ve.X[j*4])<<24 | uint32(z.Ve.X[j*4+1])<<16 | uint32(z.Ve.X[j*4+2])<<8 | uint32(z.Ve.X[j*4+3])
		w[j][1] = uint32(z.Ve1.X[j*4])<<24 | uint32(z.Ve1.X[j*4+1])<<16 | uint32(z.Ve1.X[j*4+2])<<8 | uint32(z.Ve1.X[j*4+3])
	}
	var s0, s1, t0, t1 [2]uint32
	for j := 16; j < 64; j++ {
		mpcRIGHTROTATE2(w[j-15], 7, &t0)
		mpcRIGHTROTATE2(w[j-15], 18, &t1)
		mpcXOR2(t0, t1, &t0)
		mpcRIGHTSHIFT2(w[j-15], 3, &t1)
		mpcXOR2(t0, t1, &s0)

		mpcRIGHTROTATE2(w[j-2], 17, &t0)
		mpcRIGHTROTATE2(w[j-2], 19, &t1)
		mpcXOR2(t0, t1, &t0)
		mpcRIGHTSHIFT2(w[j-2], 10, &t1)
		mpcXOR2(t0, t1, &s1)

		if !mpcADDVerify(w[j-16], s0, &t1, z.Ve, z.Ve1, randomness, &randCount, &countY) {
			return false
		}
		if !mpcADDVerify(w[j-7], t1, &t1, z.Ve, z.Ve1, randomness, &randCount, &countY) {
			return false
		}
		if !mpcADDVerify(t1, s1, &w[j], z.Ve, z.Ve1, randomness, &randCount, &countY) {
			return false
		}
	}
	va := [2]uint32{h256[0], h256[0]}
	vb := [2]uint32{h256[1], h256[1]}
	vc := [2]uint32{h256[2], h256[2]}
	vd := [2]uint32{h256[3], h256[3]}
	ve2 := [2]uint32{h256[4], h256[4]}
	vf := [2]uint32{h256[5], h256[5]}
	vg := [2]uint32{h256[6], h256[6]}
	vh := [2]uint32{h256[7], h256[7]}
	var temp1, temp2, maj [2]uint32
	for i := 0; i < 64; i++ {
		mpcRIGHTROTATE2(ve2, 6, &t0)
		mpcRIGHTROTATE2(ve2, 11, &t1)
		mpcXOR2(t0, t1, &t0)
		mpcRIGHTROTATE2(ve2, 25, &t1)
		mpcXOR2(t0, t1, &s1)

		if !mpcADDVerify(vh, s1, &t0, z.Ve, z.Ve1, randomness, &randCount, &countY) {
			return false
		}
		if !mpcCHVerify(ve2, vf, vg, &t1, z.Ve, z.Ve1, randomness, &randCount, &countY) {
			return false
		}
		if !mpcADDVerify(t0, t1, &t1, z.Ve, z.Ve1, randomness, &randCount, &countY) {
			return false
		}
		kConst := [2]uint32{k[i], k[i]}
		if !mpcADDVerify(t1, kConst, &t1, z.Ve, z.Ve1, randomness, &randCount, &countY) {
			return false
		}
		if !mpcADDVerify(t1, w[i], &temp1, z.Ve, z.Ve1, randomness, &randCount, &countY) {
			return false
		}

		mpcRIGHTROTATE2(va, 2, &t0)
		mpcRIGHTROTATE2(va, 13, &t1)
		mpcXOR2(t0, t1, &t0)
		mpcRIGHTROTATE2(va, 22, &t1)
		mpcXOR2(t0, t1, &s0)

		if !mpcMAJVerify(va, vb, vc, &maj, z.Ve, z.Ve1, randomness, &randCount, &countY) {
			return false
		}
		if !mpcADDVerify(s0, maj, &temp2, z.Ve, z.Ve1, randomness, &randCount, &countY) {
			return false
		}

		vh = vg
		vg = vf
		vf = ve2
		if !mpcADDVerify(vd, temp1, &ve2, z.Ve, z.Ve1, randomness, &randCount, &countY) {
			return false
		}
		vd = vc
		vc = vb
		vb = va
		if !mpcADDVerify(temp1, temp2, &va, z.Ve, z.Ve1, randomness, &randCount, &countY) {
			return false
		}
	}
	hHa := [8][2]uint32{
		{h256[0], h256[0]},
		{h256[1], h256[1]},
		{h256[2], h256[2]},
		{h256[3], h256[3]},
		{h256[4], h256[4]},
		{h256[5], h256[5]},
		{h256[6], h256[6]},
		{h256[7], h256[7]},
	}
	if !mpcADDVerify(hHa[0], va, &hHa[0], z.Ve, z.Ve1, randomness, &randCount, &countY) {
		return false
	}
	if !mpcADDVerify(hHa[1], vb, &hHa[1], z.Ve, z.Ve1, randomness, &randCount, &countY) {
		return false
	}
	if !mpcADDVerify(hHa[2], vc, &hHa[2], z.Ve, z.Ve1, randomness, &randCount, &countY) {
		return false
	}
	if !mpcADDVerify(hHa[3], vd, &hHa[3], z.Ve, z.Ve1, randomness, &randCount, &countY) {
		return false
	}
	if !mpcADDVerify(hHa[4], ve2, &hHa[4], z.Ve, z.Ve1, randomness, &randCount, &countY) {
		return false
	}
	if !mpcADDVerify(hHa[5], vf, &hHa[5], z.Ve, z.Ve1, randomness, &randCount, &countY) {
		return false
	}
	if !mpcADDVerify(hHa[6], vg, &hHa[6], z.Ve, z.Ve1, randomness, &randCount, &countY) {
		return false
	}
	if !mpcADDVerify(hHa[7], vh, &hHa[7], z.Ve, z.Ve1, randomness, &randCount, &countY) {
		return false
	}
	return true
}
