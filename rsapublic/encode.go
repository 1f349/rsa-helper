package rsapublic

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
)

func Write(filename string, key *rsa.PublicKey) error {
	return WritePerms(filename, key, 0600)
}

func WritePerms(filename string, key *rsa.PublicKey, perm os.FileMode) error {
	return os.WriteFile(filename, Encode(key), perm)
}

func Encode(key *rsa.PublicKey) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(key),
	})
}
