package zkboo

import "fmt"

func mpcSHA256(inputs [3][]byte, numBits int, randomness [3][]byte, views *[3]View) ([3][32]byte, error) {
	if numBits > 447 {
		return [3][32]byte{}, fmt.Errorf("input too long")
	}
	randCount := 0
	countY := 0
	chars := numBits >> 3
	var chunks [3][64]byte
	var w [64][3]uint32
	for i := 0; i < 3; i++ {
		copy(chunks[i][:], inputs[i][:chars])
		chunks[i][chars] = 0x80
		chunks[i][62] = byte(numBits >> 8)
		chunks[i][63] = byte(numBits)
		copy(views[i].X[:], chunks[i][:])
		for j := 0; j < 16; j++ {
			w[j][i] = uint32(chunks[i][j*4])<<24 | uint32(chunks[i][j*4+1])<<16 |
				uint32(chunks[i][j*4+2])<<8 | uint32(chunks[i][j*4+3])
		}
	}
	var s0, s1, t0, t1 [3]uint32
	for j := 16; j < 64; j++ {
		mpcRIGHTROTATE(w[j-15], 7, &t0)
		mpcRIGHTROTATE(w[j-15], 18, &t1)
		mpcXOR(t0, t1, &t0)
		mpcRIGHTSHIFT(w[j-15], 3, &t1)
		mpcXOR(t0, t1, &s0)

		mpcRIGHTROTATE(w[j-2], 17, &t0)
		mpcRIGHTROTATE(w[j-2], 19, &t1)
		mpcXOR(t0, t1, &t0)
		mpcRIGHTSHIFT(w[j-2], 10, &t1)
		mpcXOR(t0, t1, &s1)

		mpcADD(w[j-16], s0, &t1, randomness, &randCount, views, &countY)
		mpcADD(w[j-7], t1, &t1, randomness, &randCount, views, &countY)
		mpcADD(t1, s1, &w[j], randomness, &randCount, views, &countY)
	}
	a := [3]uint32{h256[0], h256[0], h256[0]}
	b := [3]uint32{h256[1], h256[1], h256[1]}
	c := [3]uint32{h256[2], h256[2], h256[2]}
	d := [3]uint32{h256[3], h256[3], h256[3]}
	e := [3]uint32{h256[4], h256[4], h256[4]}
	f := [3]uint32{h256[5], h256[5], h256[5]}
	g := [3]uint32{h256[6], h256[6], h256[6]}
	h := [3]uint32{h256[7], h256[7], h256[7]}
	var temp1, temp2, maj [3]uint32
	for i := 0; i < 64; i++ {
		mpcRIGHTROTATE(e, 6, &t0)
		mpcRIGHTROTATE(e, 11, &t1)
		mpcXOR(t0, t1, &t0)
		mpcRIGHTROTATE(e, 25, &t1)
		mpcXOR(t0, t1, &s1)

		mpcADD(h, s1, &t0, randomness, &randCount, views, &countY)
		mpcCH(e, f, g, &t1, randomness, &randCount, views, &countY)
		mpcADD(t0, t1, &t1, randomness, &randCount, views, &countY)
		mpcADDK(t1, k[i], &t1, randomness, &randCount, views, &countY)
		mpcADD(t1, w[i], &temp1, randomness, &randCount, views, &countY)

		mpcRIGHTROTATE(a, 2, &t0)
		mpcRIGHTROTATE(a, 13, &t1)
		mpcXOR(t0, t1, &t0)
		mpcRIGHTROTATE(a, 22, &t1)
		mpcXOR(t0, t1, &s0)

		mpcMAJ(a, b, c, &maj, randomness, &randCount, views, &countY)
		mpcADD(s0, maj, &temp2, randomness, &randCount, views, &countY)

		h = g
		g = f
		f = e
		mpcADD(d, temp1, &e, randomness, &randCount, views, &countY)
		d = c
		c = b
		b = a
		mpcADD(temp1, temp2, &a, randomness, &randCount, views, &countY)
	}
	hHa := [8][3]uint32{
		{h256[0], h256[0], h256[0]},
		{h256[1], h256[1], h256[1]},
		{h256[2], h256[2], h256[2]},
		{h256[3], h256[3], h256[3]},
		{h256[4], h256[4], h256[4]},
		{h256[5], h256[5], h256[5]},
		{h256[6], h256[6], h256[6]},
		{h256[7], h256[7], h256[7]},
	}
	mpcADD(hHa[0], a, &hHa[0], randomness, &randCount, views, &countY)
	mpcADD(hHa[1], b, &hHa[1], randomness, &randCount, views, &countY)
	mpcADD(hHa[2], c, &hHa[2], randomness, &randCount, views, &countY)
	mpcADD(hHa[3], d, &hHa[3], randomness, &randCount, views, &countY)
	mpcADD(hHa[4], e, &hHa[4], randomness, &randCount, views, &countY)
	mpcADD(hHa[5], f, &hHa[5], randomness, &randCount, views, &countY)
	mpcADD(hHa[6], g, &hHa[6], randomness, &randCount, views, &countY)
	mpcADD(hHa[7], h, &hHa[7], randomness, &randCount, views, &countY)
	var results [3][32]byte
	for i := 0; i < 8; i++ {
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
