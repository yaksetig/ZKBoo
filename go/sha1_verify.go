package zkboo

import (
	"crypto/sha256"
	"encoding/binary"
)

func computeH(k [16]byte, v View, r [4]byte, yLen int) [32]byte {
	h := sha256.New()
	h.Write(k[:])
	h.Write(v.X[:])
	var buf [4]byte
	for i := 0; i < yLen; i++ {
		binary.LittleEndian.PutUint32(buf[:], v.Y[i])
		h.Write(buf[:])
	}
	h.Write(r[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func outputSHA1(v View) [5]uint32 {
	var res [5]uint32
	copy(res[:], v.Y[YSizeSHA1-5:YSizeSHA1])
	return res
}

func mpcXOR2(x, y [2]uint32, z *[2]uint32) {
	z[0] = x[0] ^ y[0]
	z[1] = x[1] ^ y[1]
}

func mpcLEFTROTATE2(x [2]uint32, n uint, z *[2]uint32) {
	z[0] = leftRotate(x[0], n)
	z[1] = leftRotate(x[1], n)
}

func mpcRIGHTROTATE2(x [2]uint32, n uint, z *[2]uint32) {
	z[0] = rightRotate(x[0], n)
	z[1] = rightRotate(x[1], n)
}

func mpcRIGHTSHIFT2(x [2]uint32, n uint, z *[2]uint32) {
	z[0] = x[0] >> n
	z[1] = x[1] >> n
}

func mpcANDVerify(x, y [2]uint32, z *[2]uint32, ve, ve1 View, randomness [2][]byte, randCount, countY *int) bool {
	r := [2]uint32{
		getRandom32(randomness[0], *randCount),
		getRandom32(randomness[1], *randCount),
	}
	*randCount += 4
	t := (x[0] & y[1]) ^ (x[1] & y[0]) ^ (x[0] & y[0]) ^ r[0] ^ r[1]
	if ve.Y[*countY] != t {
		return false
	}
	z[0] = t
	z[1] = ve1.Y[*countY]
	*countY++
	return true
}

func mpcADDVerify(x, y [2]uint32, z *[2]uint32, ve, ve1 View, randomness [2][]byte, randCount, countY *int) bool {
	r := [2]uint32{
		getRandom32(randomness[0], *randCount),
		getRandom32(randomness[1], *randCount),
	}
	*randCount += 4
	for i := uint(0); i < 31; i++ {
		a0 := getBit(x[0]^ve.Y[*countY], i)
		a1 := getBit(x[1]^ve1.Y[*countY], i)
		b0 := getBit(y[0]^ve.Y[*countY], i)
		b1 := getBit(y[1]^ve1.Y[*countY], i)
		t := (a0 & b1) ^ (a1 & b0) ^ getBit(r[1], i)
		if getBit(ve.Y[*countY], i+1) != t^(a0&b0)^getBit(ve.Y[*countY], i)^getBit(r[0], i) {
			return false
		}
	}
	z[0] = x[0] ^ y[0] ^ ve.Y[*countY]
	z[1] = x[1] ^ y[1] ^ ve1.Y[*countY]
	*countY++
	return true
}

func mpcMAJVerify(a, b, c [2]uint32, z *[2]uint32, ve, ve1 View, randomness [2][]byte, randCount, countY *int) bool {
	var t0, t1 [2]uint32
	mpcXOR2(a, b, &t0)
	mpcXOR2(a, c, &t1)
	if !mpcANDVerify(t0, t1, z, ve, ve1, randomness, randCount, countY) {
		return false
	}
	mpcXOR2(*z, a, z)
	return true
}

func mpcCHVerify(e, f, g [2]uint32, z *[2]uint32, ve, ve1 View, randomness [2][]byte, randCount, countY *int) bool {
	var t0 [2]uint32
	mpcXOR2(f, g, &t0)
	if !mpcANDVerify(e, t0, &t0, ve, ve1, randomness, randCount, countY) {
		return false
	}
	mpcXOR2(t0, g, z)
	return true
}

func verifySHA1(a A, e int, z Z) bool {
	hash := computeH(z.Ke, z.Ve, z.Re, YSizeSHA1)
	if a.H[e] != hash {
		return false
	}
	hash = computeH(z.Ke1, z.Ve1, z.Re1, YSizeSHA1)
	if a.H[(e+1)%3] != hash {
		return false
	}

	res := outputSHA1(z.Ve)
	for i := 0; i < 5; i++ {
		if a.Yp[e][i] != res[i] {
			return false
		}
	}
	res = outputSHA1(z.Ve1)
	for i := 0; i < 5; i++ {
		if a.Yp[(e+1)%3][i] != res[i] {
			return false
		}
	}

	var rand0 [RandomnessSizeSHA1]byte
	if err := getAllRandomness(z.Ke, rand0[:]); err != nil {
		return false
	}
	var rand1 [RandomnessSizeSHA1]byte
	if err := getAllRandomness(z.Ke1, rand1[:]); err != nil {
		return false
	}
	randomness := [2][]byte{rand0[:], rand1[:]}
	randCount := 0
	countY := 0

	var w [80][2]uint32
	for j := 0; j < 16; j++ {
		w[j][0] = uint32(z.Ve.X[j*4])<<24 | uint32(z.Ve.X[j*4+1])<<16 | uint32(z.Ve.X[j*4+2])<<8 | uint32(z.Ve.X[j*4+3])
		w[j][1] = uint32(z.Ve1.X[j*4])<<24 | uint32(z.Ve1.X[j*4+1])<<16 | uint32(z.Ve1.X[j*4+2])<<8 | uint32(z.Ve1.X[j*4+3])
	}
	var temp [2]uint32
	for j := 16; j < 80; j++ {
		mpcXOR2(w[j-3], w[j-8], &temp)
		mpcXOR2(temp, w[j-14], &temp)
		mpcXOR2(temp, w[j-16], &temp)
		mpcLEFTROTATE2(temp, 1, &w[j])
	}

	va := [2]uint32{hA[0], hA[0]}
	vb := [2]uint32{hA[1], hA[1]}
	vc := [2]uint32{hA[2], hA[2]}
	vd := [2]uint32{hA[3], hA[3]}
	ve2 := [2]uint32{hA[4], hA[4]}
	var f [2]uint32
	var k uint32
	var temp1 [2]uint32

	for i := 0; i < 80; i++ {
		if i <= 19 {
			mpcXOR2(vc, vd, &f)
			if !mpcANDVerify(vb, f, &f, z.Ve, z.Ve1, randomness, &randCount, &countY) {
				return false
			}
			mpcXOR2(vd, f, &f)
			k = 0x5A827999
		} else if i <= 39 {
			mpcXOR2(vb, vc, &f)
			mpcXOR2(vd, f, &f)
			k = 0x6ED9EBA1
		} else if i <= 59 {
			if !mpcMAJVerify(vb, vc, vd, &f, z.Ve, z.Ve1, randomness, &randCount, &countY) {
				return false
			}
			k = 0x8F1BBCDC
		} else {
			mpcXOR2(vb, vc, &f)
			mpcXOR2(vd, f, &f)
			k = 0xCA62C1D6
		}

		mpcLEFTROTATE2(va, 5, &temp)
		if !mpcADDVerify(f, temp, &temp, z.Ve, z.Ve1, randomness, &randCount, &countY) {
			return false
		}
		if !mpcADDVerify(ve2, temp, &temp, z.Ve, z.Ve1, randomness, &randCount, &countY) {
			return false
		}
		temp1[0], temp1[1] = k, k
		if !mpcADDVerify(temp, temp1, &temp, z.Ve, z.Ve1, randomness, &randCount, &countY) {
			return false
		}
		if !mpcADDVerify(w[i], temp, &temp, z.Ve, z.Ve1, randomness, &randCount, &countY) {
			return false
		}
		ve2 = vd
		vd = vc
		mpcLEFTROTATE2(vb, 30, &vc)
		vb = va
		va = temp
	}

	hHa := [5][2]uint32{
		{hA[0], hA[0]},
		{hA[1], hA[1]},
		{hA[2], hA[2]},
		{hA[3], hA[3]},
		{hA[4], hA[4]},
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

	return true
}
