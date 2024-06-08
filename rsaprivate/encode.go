package rsaprivate

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
)

func Write(filename string, key *rsa.PrivateKey) error {
	return WritePerms(filename, key, 0600)
}

func WritePerms(filename string, key *rsa.PrivateKey, perm os.FileMode) error {
	return os.WriteFile(filename, Encode(key), perm)
}

func Encode(key *rsa.PrivateKey) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
}
