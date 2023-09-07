package vaulthelper

import (
	"crypto/ecdsa"
	b64 "encoding/base64"

	"github.com/fasibio/vaulthelper/helper"
)

type Base64PublicPem string

func NewBase64PublicPem(publicKey *ecdsa.PublicKey) (Base64PublicPem, error) {
	encodeKey, err := helper.EncodePublicKey(publicKey)
	if err != nil {
		return "", nil
	}
	return Base64PublicPem(b64.StdEncoding.EncodeToString([]byte(encodeKey))), err
}

func (b Base64PublicPem) Encrypt(value string) (string, error) {
	key, err := b.GetPublicKey()
	if err != nil {
		return "", err
	}
	res, err := helper.Encrypt(key, value)
	return string(res), err
}

func (b Base64PublicPem) GetIdentityId(vaultid string) (string, error) {
	key, err := b.GetPublicKey()
	if err != nil {
		return "", err
	}
	return helper.GetIdFromPublicKey(key, vaultid)
}

func (b Base64PublicPem) GetPublicKey() (*ecdsa.PublicKey, error) {

	publicPem, err := b64.StdEncoding.DecodeString(string(b))
	if err != nil {
		return nil, err
	}
	return helper.DecodePublicKey(string(publicPem))

}
