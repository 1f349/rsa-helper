package rsaprivate

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"os"
)

const readLimit = 10240 // 10 KiB

var ErrInvalidRsaPrivateKeyPemBlock = errors.New("invalid rsa private key pem block")

func Read(filename string) (*rsa.PrivateKey, error) {
	open, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer func() { _ = open.Close() }()
	return Decode(open)
}

func Decode(r io.Reader) (*rsa.PrivateKey, error) {
	// add hard limit
	limitReader := io.LimitReader(r, readLimit)
	raw, err := io.ReadAll(limitReader)
	if err != nil {
		return nil, err
	}

	// decode pem block from raw bytes
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, ErrInvalidRsaPrivateKeyPemBlock
	}

	// parse private key from pem block
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return key, nil
}
