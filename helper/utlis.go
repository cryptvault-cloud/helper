package helper

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"hash"
	"io"
	"strconv"

	"golang.org/x/crypto/poly1305"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func getCryptoRandVec(rand io.Reader, len int) []byte {
	out := make([]byte, len)
	_, err := io.ReadFull(rand, out)
	check(err)
	return out
}

func to32ByteArray(in []byte) *[32]byte {
	if len(in) != 32 {
		panic("Input array size does not match. Expected 32, but got " + strconv.Itoa(len(in)))
	}
	var out [32]byte
	for i := 0; i < 32; i++ {
		out[i] = in[i]
	}

	return &out
}

func to16ByteArray(in []byte) *[16]byte {
	if len(in) != 16 {
		panic("Input array size does not match. Expected 16, but got " + strconv.Itoa(len(in)))
	}
	var out [16]byte
	for i := 0; i < 16; i++ {
		out[i] = in[i]
	}

	return &out
}

func decryptSymmetric(in, key []byte) []byte {
	block, err := aes.NewCipher(key)
	check(err)

	cipher := cipher.NewCTR(block, in[:aes.BlockSize])

	out := make([]byte, len(in)-aes.BlockSize)
	cipher.XORKeyStream(out, in[aes.BlockSize:])

	return out
}

// Key-Derivation Function
func kdf(hash hash.Hash, shared, s1 []byte) []byte {
	hash.Write(shared)
	if s1 != nil {
		hash.Write(s1)
	}
	key := hash.Sum(nil)
	hash.Reset()
	return key
}

func verifyTag(mac *[16]byte, in, shared []byte, key *[32]byte) bool {
	return poly1305.Verify(mac, append(in, shared...), key)
}

func deriveShared(private *ecdsa.PrivateKey, public *ecdsa.PublicKey, keySize int) []byte {
	if private.PublicKey.Curve != public.Curve {
		panic("Curves don't match")
	}
	if 2*keySize > (public.Curve.Params().BitSize+7)/8 {
		panic("Shared key length is too long")
	}

	x, _ := public.Curve.ScalarMult(public.X, public.Y, private.D.Bytes())
	if x == nil {
		panic("Scalar multiplication resulted in infinity")
	}

	shared := x.Bytes()
	return shared
}

func sumTag(in, shared []byte, key *[32]byte) [16]byte {
	var out [16]byte

	poly1305.Sum(&out, append(in, shared...), key)
	return out
}

func encryptSymmetric(rand io.Reader, in, key []byte) []byte {
	block, err := aes.NewCipher(key)
	check(err)

	nonce := getCryptoRandVec(rand, aes.BlockSize)
	cipher := cipher.NewCTR(block, nonce)

	out := make([]byte, len(in))
	cipher.XORKeyStream(out, in)

	out = append(nonce, out...)
	return out
}
