package rsapublic

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"os"
)

const readLimit = 10240 // 10 KiB

var ErrInvalidRsaPublicKeyPemBlock = errors.New("invalid rsa public key pem block")

func Read(filename string) (*rsa.PublicKey, error) {
	open, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer func() { _ = open.Close() }()
	return Decode(open)
}

func Decode(r io.Reader) (*rsa.PublicKey, error) {
	// add hard limit
	limitReader := io.LimitReader(r, readLimit)
	raw, err := io.ReadAll(limitReader)
	if err != nil {
		return nil, err
	}

	// decode pem block from raw bytes
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "RSA PUBLIC KEY" {
		return nil, ErrInvalidRsaPublicKeyPemBlock
	}

	// parse private key from pem block
	key, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return key, nil
}
