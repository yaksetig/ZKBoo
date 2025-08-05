package zkboo

import (
	"encoding/binary"
	"fmt"
)

func getRandom32(randomness []byte, offset int) uint32 {
	return binary.LittleEndian.Uint32(randomness[offset : offset+4])
}

func getBit(x uint32, i uint) uint32 {
	return (x >> i) & 1
}

func setBit(x uint32, i uint, b uint32) uint32 {
	if b&1 == 1 {
		return x | (1 << i)
	}
	return x & ^(1 << i)
}

func mpcXOR(x, y [3]uint32, z *[3]uint32) {
	z[0] = x[0] ^ y[0]
	z[1] = x[1] ^ y[1]
	z[2] = x[2] ^ y[2]
}

func mpcAND(x, y [3]uint32, z *[3]uint32, randomness [3][]byte, randCount *int, views *[3]View, countY *int) {
	r := [3]uint32{
		getRandom32(randomness[0], *randCount),
		getRandom32(randomness[1], *randCount),
		getRandom32(randomness[2], *randCount),
	}
	*randCount += 4
	t := [3]uint32{}
	t[0] = (x[0] & y[1]) ^ (x[1] & y[0]) ^ (x[0] & y[0]) ^ r[0] ^ r[1]
	t[1] = (x[1] & y[2]) ^ (x[2] & y[1]) ^ (x[1] & y[1]) ^ r[1] ^ r[2]
	t[2] = (x[2] & y[0]) ^ (x[0] & y[2]) ^ (x[2] & y[2]) ^ r[2] ^ r[0]
	z[0] = t[0]
	z[1] = t[1]
	z[2] = t[2]
	views[0].Y[*countY] = z[0]
	views[1].Y[*countY] = z[1]
	views[2].Y[*countY] = z[2]
	(*countY)++
}

func mpcNEGATE(x [3]uint32, z *[3]uint32) {
	z[0] = ^x[0]
	z[1] = ^x[1]
	z[2] = ^x[2]
}

func mpcADD(x, y [3]uint32, z *[3]uint32, randomness [3][]byte, randCount *int, views *[3]View, countY *int) {
	c := [3]uint32{}
	r := [3]uint32{
		getRandom32(randomness[0], *randCount),
		getRandom32(randomness[1], *randCount),
		getRandom32(randomness[2], *randCount),
	}
	*randCount += 4
	for i := uint(0); i < 31; i++ {
		a0 := getBit(x[0]^c[0], i)
		a1 := getBit(x[1]^c[1], i)
		a2 := getBit(x[2]^c[2], i)
		b0 := getBit(y[0]^c[0], i)
		b1 := getBit(y[1]^c[1], i)
		b2 := getBit(y[2]^c[2], i)
		t := (a0 & b1) ^ (a1 & b0) ^ getBit(r[1], i)
		c[0] = setBit(c[0], i+1, t^(a0&b0)^getBit(c[0], i)^getBit(r[0], i))
		t = (a1 & b2) ^ (a2 & b1) ^ getBit(r[2], i)
		c[1] = setBit(c[1], i+1, t^(a1&b1)^getBit(c[1], i)^getBit(r[1], i))
		t = (a2 & b0) ^ (a0 & b2) ^ getBit(r[0], i)
		c[2] = setBit(c[2], i+1, t^(a2&b2)^getBit(c[2], i)^getBit(r[2], i))
	}
	z[0] = x[0] ^ y[0] ^ c[0]
	z[1] = x[1] ^ y[1] ^ c[1]
	z[2] = x[2] ^ y[2] ^ c[2]
	views[0].Y[*countY] = c[0]
	views[1].Y[*countY] = c[1]
	views[2].Y[*countY] = c[2]
	(*countY)++
}

func mpcADDK(x [3]uint32, y uint32, z *[3]uint32, randomness [3][]byte, randCount *int, views *[3]View, countY *int) {
	c := [3]uint32{}
	r := [3]uint32{
		getRandom32(randomness[0], *randCount),
		getRandom32(randomness[1], *randCount),
		getRandom32(randomness[2], *randCount),
	}
	*randCount += 4
	for i := uint(0); i < 31; i++ {
		a0 := getBit(x[0]^c[0], i)
		a1 := getBit(x[1]^c[1], i)
		a2 := getBit(x[2]^c[2], i)
		b0 := getBit(y^c[0], i)
		b1 := getBit(y^c[1], i)
		b2 := getBit(y^c[2], i)
		t := (a0 & b1) ^ (a1 & b0) ^ getBit(r[1], i)
		c[0] = setBit(c[0], i+1, t^(a0&b0)^getBit(c[0], i)^getBit(r[0], i))
		t = (a1 & b2) ^ (a2 & b1) ^ getBit(r[2], i)
		c[1] = setBit(c[1], i+1, t^(a1&b1)^getBit(c[1], i)^getBit(r[1], i))
		t = (a2 & b0) ^ (a0 & b2) ^ getBit(r[0], i)
		c[2] = setBit(c[2], i+1, t^(a2&b2)^getBit(c[2], i)^getBit(r[2], i))
	}
	z[0] = x[0] ^ y ^ c[0]
	z[1] = x[1] ^ y ^ c[1]
	z[2] = x[2] ^ y ^ c[2]
	views[0].Y[*countY] = c[0]
	views[1].Y[*countY] = c[1]
	views[2].Y[*countY] = c[2]
	(*countY)++
}

func mpcRIGHTROTATE(x [3]uint32, n uint, z *[3]uint32) {
	z[0] = rightRotate(x[0], n)
	z[1] = rightRotate(x[1], n)
	z[2] = rightRotate(x[2], n)
}

func mpcLEFTROTATE(x [3]uint32, n uint, z *[3]uint32) {
	z[0] = leftRotate(x[0], n)
	z[1] = leftRotate(x[1], n)
	z[2] = leftRotate(x[2], n)
}

func mpcRIGHTSHIFT(x [3]uint32, n uint, z *[3]uint32) {
	z[0] = x[0] >> n
	z[1] = x[1] >> n
	z[2] = x[2] >> n
}

func mpcMAJ(a, b, c [3]uint32, z *[3]uint32, randomness [3][]byte, randCount *int, views *[3]View, countY *int) {
	var t0, t1 [3]uint32
	mpcXOR(a, b, &t0)
	mpcXOR(a, c, &t1)
	mpcAND(t0, t1, z, randomness, randCount, views, countY)
	mpcXOR(*z, a, z)
}

func mpcCH(e, f, g [3]uint32, z *[3]uint32, randomness [3][]byte, randCount *int, views *[3]View, countY *int) {
	var t0 [3]uint32
	mpcXOR(f, g, &t0)
	mpcAND(e, t0, &t0, randomness, randCount, views, countY)
	mpcXOR(t0, g, z)
}

func mpcSHA1(inputs [3][]byte, numBits int, randomness [3][]byte, views *[3]View) ([3][20]byte, error) {
	if numBits > 447 {
		return [3][20]byte{}, fmt.Errorf("input too long")
	}
	randCount := 0
	countY := 0
	chars := numBits >> 3
	var chunks [3][64]byte
	var w [80][3]uint32
	for i := 0; i < 3; i++ {
		copy(chunks[i][:], inputs[i][:chars])
		chunks[i][chars] = 0x80
		chunks[i][62] = byte(numBits >> 8)
		chunks[i][63] = byte(numBits)
		copy(views[i].X[:], chunks[i][:])
		for j := 0; j < 16; j++ {
			w[j][i] = uint32(chunks[i][j*4])<<24 | uint32(chunks[i][j*4+1])<<16 | uint32(chunks[i][j*4+2])<<8 | uint32(chunks[i][j*4+3])
		}
	}
	var temp, t0 [3]uint32
	for j := 16; j < 80; j++ {
		mpcXOR(w[j-3], w[j-8], &temp)
		mpcXOR(temp, w[j-14], &temp)
		mpcXOR(temp, w[j-16], &temp)
		mpcLEFTROTATE(temp, 1, &w[j])
	}
	a := [3]uint32{hA[0], hA[0], hA[0]}
	b := [3]uint32{hA[1], hA[1], hA[1]}
	c := [3]uint32{hA[2], hA[2], hA[2]}
	d := [3]uint32{hA[3], hA[3], hA[3]}
	e := [3]uint32{hA[4], hA[4], hA[4]}
	var f [3]uint32
	var k uint32
	for i := 0; i < 80; i++ {
		if i <= 19 {
			mpcXOR(c, d, &f)
			mpcAND(b, f, &f, randomness, &randCount, views, &countY)
			mpcXOR(d, f, &f)
			k = 0x5A827999
		} else if i <= 39 {
			mpcXOR(b, c, &f)
			mpcXOR(d, f, &f)
			k = 0x6ED9EBA1
		} else if i <= 59 {
			mpcMAJ(b, c, d, &f, randomness, &randCount, views, &countY)
			k = 0x8F1BBCDC
		} else {
			mpcXOR(b, c, &f)
			mpcXOR(d, f, &f)
			k = 0xCA62C1D6
		}
		mpcLEFTROTATE(a, 5, &temp)
		mpcADD(f, temp, &temp, randomness, &randCount, views, &countY)
		mpcADD(e, temp, &temp, randomness, &randCount, views, &countY)
		mpcADDK(temp, k, &temp, randomness, &randCount, views, &countY)
		mpcADD(w[i], temp, &temp, randomness, &randCount, views, &countY)
		e = d
		d = c
		mpcLEFTROTATE(b, 30, &c)
		b = a
		a = temp
	}
	hHa := [5][3]uint32{
		{hA[0], hA[0], hA[0]},
		{hA[1], hA[1], hA[1]},
		{hA[2], hA[2], hA[2]},
		{hA[3], hA[3], hA[3]},
		{hA[4], hA[4], hA[4]},
	}
	mpcADD(hHa[0], a, &hHa[0], randomness, &randCount, views, &countY)
	mpcADD(hHa[1], b, &hHa[1], randomness, &randCount, views, &countY)
	mpcADD(hHa[2], c, &hHa[2], randomness, &randCount, views, &countY)
	mpcADD(hHa[3], d, &hHa[3], randomness, &randCount, views, &countY)
	mpcADD(hHa[4], e, &hHa[4], randomness, &randCount, views, &countY)
	var results [3][20]byte
	for i := 0; i < 5; i++ {
		mpcRIGHTSHIFT(hHa[i], 24, &t0)
		results[0][i*4] = byte(t0[0])
		results[1][i*4] = byte(t0[1])
		results[2][i*4] = byte(t0[2])
		mpcRIGHTSHIFT(hHa[i], 16, &t0)
		results[0][i*4+1] = byte(t0[0])
		results[1][i*4+1] = byte(t0[1])
		results[2][i*4+1] = byte(t0[2])
		mpcRIGHTSHIFT(hHa[i], 8, &t0)
		results[0][i*4+2] = byte(t0[0])
		results[1][i*4+2] = byte(t0[1])
		results[2][i*4+2] = byte(t0[2])
		results[0][i*4+3] = byte(hHa[i][0])
		results[1][i*4+3] = byte(hHa[i][1])
		results[2][i*4+3] = byte(hHa[i][2])
	}
	return results, nil
}
