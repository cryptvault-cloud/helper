package helper

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"hash"
	"io"
	"math/big"
	"strings"
	"time"

	b64 "encoding/base64"

	"golang.org/x/crypto/chacha20poly1305"
)

func GenerateNewKeyPair() (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	private, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	public := private.PublicKey
	return private, &public, nil
}

func GetPrivateKeyFromB64String(key string) (*ecdsa.PrivateKey, error) {
	privateKeyPem, err := b64.StdEncoding.DecodeString(key)
	if err != nil {
		return nil, err
	}

	return DecodePrivateKey(string(privateKeyPem))
}

func GetB64FromPrivateKey(key *ecdsa.PrivateKey) (string, error) {
	pem, err := EncodePrivateKey(key)
	if err != nil {
		return "", err
	}
	return b64.StdEncoding.EncodeToString([]byte(pem)), nil
}

func GetB64FromPublicKey(key *ecdsa.PublicKey) (string, error) {
	pem, err := EncodePublicKey(key)
	if err != nil {
		return "", err
	}
	return b64.StdEncoding.EncodeToString([]byte(pem)), nil
}

func EncodePublicKey(publicKey *ecdsa.PublicKey) (string, error) {
	x509EncodedPub, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", err
	}
	pemEncodedPub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: x509EncodedPub})

	return string(pemEncodedPub), nil
}
func EncodePrivateKey(privateKey *ecdsa.PrivateKey) (string, error) {
	x509Encoded, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return "", err
	}
	pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x509Encoded})

	return string(pemEncoded), nil
}
func Encode(privateKey *ecdsa.PrivateKey, publicKey *ecdsa.PublicKey) (string, string, error) {
	pemEncodedPriv, err := EncodePrivateKey(privateKey)
	if err != nil {
		return "", "", err
	}
	pemEncodedPub, err := EncodePublicKey(publicKey)
	if err != nil {
		return "", "", err
	}

	return pemEncodedPriv, pemEncodedPub, nil
}

func Decode(pemEncoded string, pemEncodedPub string) (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemEncoded))
	x509Encoded := block.Bytes
	privateKey, err := x509.ParseECPrivateKey(x509Encoded)
	if err != nil {
		return nil, nil, err
	}
	blockPub, _ := pem.Decode([]byte(pemEncodedPub))
	x509EncodedPub := blockPub.Bytes
	genericPublicKey, err := x509.ParsePKIXPublicKey(x509EncodedPub)
	if err != nil {
		return nil, nil, err
	}
	publicKey := genericPublicKey.(*ecdsa.PublicKey)

	return privateKey, publicKey, nil
}

func DecodePrivateKey(pemEncoded string) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemEncoded))
	if block == nil {
		return nil, fmt.Errorf("unable to decode %s", pemEncoded)
	}
	x509Encoded := block.Bytes
	privateKey, err := x509.ParseECPrivateKey(x509Encoded)
	return privateKey, err
}

func DecodePublicKey(pemEncodedPub string) (*ecdsa.PublicKey, error) {
	blockPub, _ := pem.Decode([]byte(pemEncodedPub))
	x509EncodedPub := blockPub.Bytes
	genericPublicKey, err := x509.ParsePKIXPublicKey(x509EncodedPub)
	if err != nil {
		return nil, err
	}
	res := genericPublicKey.(*ecdsa.PublicKey)
	return res, nil
}

func Sign(privatekey *ecdsa.PrivateKey, message string) (string, error) {

	var h = sha256.New()

	_, err := io.WriteString(h, message)
	if err != nil {
		return "", err
	}
	signhash := h.Sum(nil)

	r, s, serr := ecdsa.Sign(rand.Reader, privatekey, signhash)
	if serr != nil {
		return "", serr
	}
	return fmt.Sprintf("%s-%s", b64.StdEncoding.EncodeToString(r.Bytes()), b64.StdEncoding.EncodeToString(s.Bytes())), nil
}

type Message struct {
	Expired  time.Time `json:"exp,omitempty"`
	IssuedAt time.Time `json:"iat,omitempty"`
	VaultId  string    `json:"vault_id,omitempty"`
	TokenId  string    `json:"token_id,omitempty"`
}

type JwtHeader struct {
	Type      string `json:"typ,omitempty"`
	Algorithm string `json:"alg,omitempty"`
}

func getHeaderString() (string, error) {
	res, err := json.Marshal(JwtHeader{
		Type:      "JWT",
		Algorithm: "P-521",
	})

	return b64.StdEncoding.EncodeToString(res), err
}

func GetIdFromPublicKey(publicKey *ecdsa.PublicKey, vaultId string) (string, error) {
	encodeKey, err := EncodePublicKey(publicKey)
	if err != nil {
		return "", nil
	}
	b64pem := b64.StdEncoding.EncodeToString([]byte(encodeKey))
	h := sha256.New()
	_, err = h.Write([]byte(vaultId))
	if err != nil {
		return "", err
	}
	_, err = h.Write([]byte(b64pem))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

type SignCreatorMessage struct {
	IssuedAt       time.Time `json:"iat,omitempty"`
	VaultId        string    `json:"vault_id,omitempty"`
	CreatorTokenId string    `json:"creator_token_id,omitempty"`
	TokenId        string    `json:"token_id,omitempty"`
}

func SignCreatorJWT(private *ecdsa.PrivateKey, childTokenId, vaultId string) (string, error) {
	tokenID, err := GetIdFromPublicKey(&private.PublicKey, vaultId)
	if err != nil {
		return "", err
	}
	m := SignCreatorMessage{
		IssuedAt:       time.Now(),
		VaultId:        vaultId,
		CreatorTokenId: tokenID,
		TokenId:        childTokenId,
	}
	mjson, err := json.Marshal(&m)
	if err != nil {
		return "", err
	}
	header, err := getHeaderString()
	if err != nil {
		return "", err
	}

	sign, err := Sign(private, string(mjson))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s.%s.%s", header, b64.StdEncoding.EncodeToString(mjson), sign), nil
}

func SignJWT(private *ecdsa.PrivateKey, vaultId string) (string, error) {
	tokenID, err := GetIdFromPublicKey(&private.PublicKey, vaultId)
	if err != nil {
		return "", err
	}
	m := Message{
		Expired:  time.Now().Add(5 * time.Minute),
		IssuedAt: time.Now(),
		VaultId:  vaultId,
		TokenId:  tokenID,
	}
	mjson, err := json.Marshal(&m)
	if err != nil {
		return "", err
	}
	header, err := getHeaderString()
	if err != nil {
		return "", err
	}

	sign, err := Sign(private, string(mjson))
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%s.%s.%s", header, b64.StdEncoding.EncodeToString(mjson), sign), nil
}

func DecodeCreatorJWT(jwt string) (*SignCreatorMessage, string, error) {
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return nil, "", fmt.Errorf("JWT invalid part size")
	}

	var header JwtHeader
	headerjson, err := b64.StdEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, "", err
	}
	err = json.Unmarshal(headerjson, &header)
	if err != nil {
		return nil, "", err
	}
	if header.Algorithm != "P-521" {
		return nil, "", fmt.Errorf("invalid Alg")
	}
	if header.Type != "JWT" {
		return nil, "", fmt.Errorf("invalid Type")
	}
	var message SignCreatorMessage
	messagejson, err := b64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, "", err
	}
	err = json.Unmarshal(messagejson, &message)
	if err != nil {
		return nil, "", err
	}
	return &message, string(messagejson), nil
}

func DecodeJWT(jwt string) (*Message, string, error) {
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return nil, "", fmt.Errorf("JWT invalid part size")
	}

	var header JwtHeader
	headerjson, err := b64.StdEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, "", err
	}
	err = json.Unmarshal(headerjson, &header)
	if err != nil {
		return nil, "", err
	}
	if header.Algorithm != "P-521" {
		return nil, "", fmt.Errorf("invalid Alg")
	}
	if header.Type != "JWT" {
		return nil, "", fmt.Errorf("invalid Type")
	}
	var message Message
	messagejson, err := b64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, "", err
	}
	err = json.Unmarshal(messagejson, &message)
	if err != nil {
		return nil, "", err
	}
	return &message, string(messagejson), nil
}

func VerifyCreatorJWT(pubkey *ecdsa.PublicKey, jwt string) (*SignCreatorMessage, error) {
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("JWT invalid part size")
	}
	message, messagejson, err := DecodeCreatorJWT(jwt)
	if err != nil {
		return nil, err
	}
	_, err = Verify(pubkey, messagejson, parts[2])
	if err != nil {
		return nil, err
	}
	return message, nil
}

func VerifyJWT(pubkey *ecdsa.PublicKey, jwt string) (*Message, error) {
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("JWT invalid part size")
	}
	message, messagejson, err := DecodeJWT(jwt)
	if err != nil {
		return nil, err
	}
	_, err = Verify(pubkey, messagejson, parts[2])
	if err != nil {
		return nil, err
	}
	return message, nil
}

func Verify(pubkey *ecdsa.PublicKey, message, signature string) (bool, error) {

	splitarr := strings.Split(signature, "-")
	if len(splitarr) != 2 {
		return false, fmt.Errorf("error split signature get not exactly a list with two elements got %s ", signature)
	}
	rb, err := b64.StdEncoding.DecodeString(splitarr[0])
	if err != nil {
		return false, err
	}
	sb, err := b64.StdEncoding.DecodeString(splitarr[1])
	if err != nil {
		return false, err
	}

	r := big.NewInt(0)
	s := big.NewInt(0)
	r = r.SetBytes(rb)
	s = s.SetBytes(sb)
	h := sha256.New()

	_, err = io.WriteString(h, message)
	if err != nil {
		return false, err
	}
	signhash := h.Sum(nil)
	res := ecdsa.Verify(pubkey, signhash, r, s)
	return res, nil
}

func Encrypt(pubkey *ecdsa.PublicKey, message string) ([]byte, error) {
	res, err := encrypt(rand.Reader, pubkey, []byte(message), nil, nil)
	if err != nil {
		return res, err
	}
	return []byte(b64.StdEncoding.EncodeToString(res)), nil
}
func Decrypt(private *ecdsa.PrivateKey, message string) ([]byte, error) {

	passframe, err := b64.StdEncoding.DecodeString(message)
	if err != nil {
		return nil, err
	}
	return decrypt(private, []byte(passframe), nil, nil)
}

// Decrypt is a function for decryption
func decrypt(private *ecdsa.PrivateKey, in, s1, s2 []byte) ([]byte, error) {
	curveName := private.PublicKey.Curve.Params().Name
	var hashFunc hash.Hash
	if curveName == "P-521" {
		hashFunc = sha512.New()
	} else {
		hashFunc = sha256.New()
	}
	keySize := hashFunc.Size() / 2

	var messageStart int
	macLen := chacha20poly1305.Overhead

	if in[0] == 2 || in[0] == 3 || in[0] == 4 {
		messageStart = (private.PublicKey.Curve.Params().BitSize + 7) / 4
		if len(in) < (messageStart + macLen + 1) {
			return []byte{}, fmt.Errorf("invalid message")
		}
	} else {
		return []byte{}, fmt.Errorf("invalid public key")
	}

	if curveName == "P-521" {
		messageStart++
	}

	messageEnd := len(in) - macLen

	R := new(ecdsa.PublicKey)
	R.Curve = private.PublicKey.Curve
	R.X, R.Y = elliptic.Unmarshal(R.Curve, in[:messageStart])
	if R.X == nil {
		panic("Invalid public key. Maybe you didn't specify the right mode?")
	}
	if !R.Curve.IsOnCurve(R.X, R.Y) {
		panic("Invalid curve")
	}

	shared := deriveShared(private, R, keySize)

	K := kdf(hashFunc, shared, s1)

	Ke := K[:keySize]
	Km := K[keySize:]
	if len(Km) < 32 {
		hashFunc.Write(Km)
		Km = hashFunc.Sum(nil)
		hashFunc.Reset()
	}

	match := verifyTag(to16ByteArray(in[messageEnd:]), in[messageStart:messageEnd], s2, to32ByteArray(Km))
	if !match {
		panic("Message tags don't match")
	}

	out := decryptSymmetric(in[messageStart:messageEnd], Ke)
	return out, nil
}

// Encrypt is a function for encryption
func encrypt(rand io.Reader, public *ecdsa.PublicKey, in, s1, s2 []byte) ([]byte, error) {
	private, err := ecdsa.GenerateKey(public.Curve, rand)
	if err != nil {
		return []byte{}, err
	}

	curveName := public.Curve.Params().Name
	var hashFunc hash.Hash
	if curveName == "P-521" {
		hashFunc = sha512.New()
	} else {
		hashFunc = sha256.New()
	}
	keySize := hashFunc.Size() / 2

	shared := deriveShared(private, public, keySize)
	K := kdf(hashFunc, shared, s1)
	Ke := K[:keySize]
	Km := K[keySize:]
	if len(Km) < 32 {
		hashFunc.Write(Km)
		Km = hashFunc.Sum(nil)
		hashFunc.Reset()
	}

	c := encryptSymmetric(rand, in, Ke)

	tag := sumTag(c, s2, to32ByteArray(Km))

	R := elliptic.Marshal(public.Curve, private.PublicKey.X, private.PublicKey.Y)
	out := make([]byte, len(R)+len(c)+len(tag))
	copy(out, R)
	copy(out[len(R):], c)
	copy(out[len(R)+len(c):], tag[:])
	return out, nil
}
