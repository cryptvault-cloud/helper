package helper

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDeAndEncrypt(t *testing.T) {
	assert := assert.New(t)
	msg := "Test123"
	privateKey, publicKey, err := GenerateNewKeyPair()
	assert.Nil(err)
	encryptMsg, err := Encrypt(publicKey, msg)
	assert.Nil(err)
	decryptMsg, err := Decrypt(privateKey, string(encryptMsg))
	assert.Nil(err)
	assert.Equal(string(decryptMsg), msg)

}
