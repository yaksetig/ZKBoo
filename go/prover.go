package zkboo

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"errors"
)

const (
	ySizeSHA1   = 370
	ySizeSHA256 = 736
)

type View struct {
	X [64]byte
	Y [ySizeSHA256]uint32
}

type A struct {
	Yp [3][8]uint32
	H  [3][32]byte
}

type Z struct {
	Ke  [16]byte
	Ke1 [16]byte
	Ve  View
	Ve1 View
	Re  [4]byte
	Re1 [4]byte
}

func getAllRandomness(key []byte, out []byte) error {
	if len(key) != 16 {
		return errors.New("key must be 16 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	iv := []byte("0123456789012345")
	stream := cipher.NewCTR(block, iv)
	zeros := make([]byte, len(out))
	stream.XORKeyStream(out, zeros)
	return nil
}

func commitHash(key [16]byte, view View, r [4]byte, ySize int) [32]byte {
	h := sha256.New()
	h.Write(key[:])
	buf := new(bytes.Buffer)
	buf.Write(view.X[:])
	binary.Write(buf, binary.BigEndian, view.Y[:ySize])
	h.Write(buf.Bytes())
	h.Write(r[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func h3(y []uint32, a A) int {
	h := sha256.New()
	for i := 0; i < len(y); i++ {
		binary.Write(h, binary.BigEndian, y[i])
	}
	binary.Write(h, binary.BigEndian, a)
	hash := h.Sum(nil)
	bitTracker := 0
	for {
		if bitTracker+1 >= len(hash)*8 {
			tmp := sha256.Sum256(hash)
			hash = tmp[:]
			bitTracker = 0
		}
		b1 := (hash[bitTracker/8] >> (bitTracker % 8)) & 1
		b2 := (hash[(bitTracker+1)/8] >> ((bitTracker + 1) % 8)) & 1
		bitTracker += 2
		v := int(b1<<1 | b2)
		if v < 3 {
			return v
		}
	}
}

func mpcSHA1(views *[3]View, shares [3][]byte) {
	for i := 0; i < 3; i++ {
		copy(views[i].X[:], shares[i])
	}
}

func mpcSHA256(views *[3]View, shares [3][]byte) {
	for i := 0; i < 3; i++ {
		copy(views[i].X[:], shares[i])
	}
}
func ProveSHA1(msg []byte) (A, Z, error) {
	if len(msg) > 64 {
		return A{}, Z{}, errors.New("message too long")
	}
	var keys [3][16]byte
	var rs [3][4]byte
	for i := 0; i < 3; i++ {
		rand.Read(keys[i][:])
		rand.Read(rs[i][:])
	}
	shares := [3][]byte{
		make([]byte, len(msg)),
		make([]byte, len(msg)),
		make([]byte, len(msg)),
	}
	rand.Read(shares[0])
	rand.Read(shares[1])
	for i := 0; i < len(msg); i++ {
		shares[2][i] = msg[i] ^ shares[0][i] ^ shares[1][i]
	}
	randomness := [3][]byte{
		make([]byte, 1472),
		make([]byte, 1472),
		make([]byte, 1472),
	}
	for i := 0; i < 3; i++ {
		getAllRandomness(keys[i][:], randomness[i])
	}
	var views [3]View
	mpcSHA1(&views, shares)
	digest := sha1.Sum(msg)
	var digestWords [8]uint32
	for i := 0; i < 5; i++ {
		digestWords[i] = binary.BigEndian.Uint32(digest[i*4:])
	}
	var outShares [3][8]uint32
	for i := 0; i < 2; i++ {
		for j := 0; j < 5; j++ {
			var b [4]byte
			rand.Read(b[:])
			outShares[i][j] = binary.BigEndian.Uint32(b[:])
		}
	}
	for j := 0; j < 5; j++ {
		outShares[2][j] = digestWords[j] ^ outShares[0][j] ^ outShares[1][j]
	}
	var aRes A
	for i := 0; i < 3; i++ {
		copy(aRes.Yp[i][:], outShares[i][:])
		for j := 0; j < 5; j++ {
			views[i].Y[ySizeSHA1-5+j] = outShares[i][j]
		}
		aRes.H[i] = commitHash(keys[i], views[i], rs[i], ySizeSHA1)
	}
	finalHash := make([]uint32, 8)
	for j := 0; j < 8; j++ {
		finalHash[j] = outShares[0][j] ^ outShares[1][j] ^ outShares[2][j]
	}
	e := h3(finalHash, aRes)
	var zRes Z
	zRes.Ke = keys[e]
	zRes.Ke1 = keys[(e+1)%3]
	zRes.Ve = views[e]
	zRes.Ve1 = views[(e+1)%3]
	zRes.Re = rs[e]
	zRes.Re1 = rs[(e+1)%3]
	return aRes, zRes, nil
}

func ProveSHA256(msg []byte) (A, Z, error) {
	if len(msg) > 64 {
		return A{}, Z{}, errors.New("message too long")
	}
	var keys [3][16]byte
	var rs [3][4]byte
	for i := 0; i < 3; i++ {
		rand.Read(keys[i][:])
		rand.Read(rs[i][:])
	}
	shares := [3][]byte{
		make([]byte, len(msg)),
		make([]byte, len(msg)),
		make([]byte, len(msg)),
	}
	rand.Read(shares[0])
	rand.Read(shares[1])
	for i := 0; i < len(msg); i++ {
		shares[2][i] = msg[i] ^ shares[0][i] ^ shares[1][i]
	}
	randomness := [3][]byte{
		make([]byte, 2912),
		make([]byte, 2912),
		make([]byte, 2912),
	}
	for i := 0; i < 3; i++ {
		getAllRandomness(keys[i][:], randomness[i])
	}
	var views [3]View
	mpcSHA256(&views, shares)
	digest := sha256.Sum256(msg)
	var digestWords [8]uint32
	for i := 0; i < 8; i++ {
		digestWords[i] = binary.BigEndian.Uint32(digest[i*4:])
	}
	var outShares [3][8]uint32
	for i := 0; i < 2; i++ {
		for j := 0; j < 8; j++ {
			var b [4]byte
			rand.Read(b[:])
			outShares[i][j] = binary.BigEndian.Uint32(b[:])
		}
	}
	for j := 0; j < 8; j++ {
		outShares[2][j] = digestWords[j] ^ outShares[0][j] ^ outShares[1][j]
	}
	var aRes A
	for i := 0; i < 3; i++ {
		copy(aRes.Yp[i][:], outShares[i][:])
		for j := 0; j < 8; j++ {
			views[i].Y[ySizeSHA256-8+j] = outShares[i][j]
		}
		aRes.H[i] = commitHash(keys[i], views[i], rs[i], ySizeSHA256)
	}
	finalHash := make([]uint32, 8)
	for j := 0; j < 8; j++ {
		finalHash[j] = outShares[0][j] ^ outShares[1][j] ^ outShares[2][j]
	}
	e := h3(finalHash, aRes)
	var zRes Z
	zRes.Ke = keys[e]
	zRes.Ke1 = keys[(e+1)%3]
	zRes.Ve = views[e]
	zRes.Ve1 = views[(e+1)%3]
	zRes.Re = rs[e]
	zRes.Re1 = rs[(e+1)%3]
	return aRes, zRes, nil
}
