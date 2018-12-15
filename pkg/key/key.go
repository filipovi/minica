package key

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
)

// New returns a new private Key
func New(fn string) (*rsa.PrivateKey, error) {
	pk, err := Read(fn)
	if err == nil {
		return pk, nil
	}
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	return Create(fn)
}

// Read the PrivateKey from the file
func Read(fn string) (*rsa.PrivateKey, error) {
	c, err := ioutil.ReadFile(fn)
	if err != nil {
		return nil, err
	}
	b, _ := pem.Decode(c)
	if b == nil {
		return nil, fmt.Errorf("no PEM found")
	}
	if b.Type != "RSA PRIVATE KEY" && b.Type != "ECDSA PRIVATE KEY" {
		return nil, fmt.Errorf("incorrect PEM type %s", b)
	}

	return x509.ParsePKCS1PrivateKey(b.Bytes)
}

// Create the private key
func Create(fn string) (*rsa.PrivateKey, error) {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	der := x509.MarshalPKCS1PrivateKey(k)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(fn, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	err = pem.Encode(f, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: der,
	})
	if err != nil {
		return nil, err
	}

	return k, nil
}

// Equals checks that the two keys are equals
func Equals(a, b interface{}) (bool, error) {
	aBytes, err := x509.MarshalPKIXPublicKey(a)
	if err != nil {
		return false, err
	}
	bBytes, err := x509.MarshalPKIXPublicKey(b)
	if err != nil {
		return false, err
	}
	return bytes.Compare(aBytes, bBytes) == 0, nil
}
