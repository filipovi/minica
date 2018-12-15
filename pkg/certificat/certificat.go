package certificat

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math"
	"math/big"
	"net"
	"os"
	"time"
)

// New returns a new private Key
func New(fn string, pk *rsa.PrivateKey) (*x509.Certificate, error) {
	c, err := Read(fn)
	if err == nil {
		return c, nil
	}
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	return Create(fn, "simpleca", pk)
}

func NewSigned(fn, cn string, pk, capk *rsa.PrivateKey, cac *x509.Certificate, ips, dns []string) (*x509.Certificate, error) {
	c, err := Read(fn)
	if err == nil {
		return c, nil
	}
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	return CreateSigned(fn, cn, pk, capk, cac, ips, dns)
}

// Read the Certificate from the file
func Read(fn string) (*x509.Certificate, error) {
	c, err := ioutil.ReadFile(fn)
	if err != nil {
		return nil, err
	}
	b, _ := pem.Decode(c)
	if b == nil {
		return nil, fmt.Errorf("no PEM found")
	} else if b.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("incorrect PEM type %s", b.Type)
	}
	return x509.ParseCertificate(b.Bytes)
}

// Create a new Certificat file
func Create(fn, cn string, pk *rsa.PrivateKey) (*x509.Certificate, error) {
	serial, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: cn + hex.EncodeToString(serial.Bytes()[:3]),
		},
		SerialNumber: serial,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(100, 0, 0),

		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, pk.Public(), pk)
	if err != nil {
		return nil, err
	}

	file, err := os.OpenFile(fn, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	if pem.Encode(file, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		return nil, err
	}

	return x509.ParseCertificate(der)
}

func parseIP(ips []string) ([]net.IP, error) {
	var parsed []net.IP
	for _, s := range ips {
		p := net.ParseIP(s)
		if p == nil {
			return nil, fmt.Errorf("invalid IP address: %s", s)
		}
		parsed = append(parsed, p)
	}

	return parsed, nil
}

// Create a new Signed Certificat file
func CreateSigned(fn, cn string, pk, capk *rsa.PrivateKey, cac *x509.Certificate, ips, dns []string) (*x509.Certificate, error) {
	serial, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
	if err != nil {
		return nil, err
	}

	parsedIPs, err := parseIP(ips)
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		DNSNames:    dns,
		IPAddresses: parsedIPs,
		Subject: pkix.Name{
			CommonName: cn,
		},
		SerialNumber: serial,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(90, 0, 0),

		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, cac, pk.Public(), capk)
	if err != nil {
		return nil, err
	}

	file, err := os.OpenFile(fn, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	if pem.Encode(file, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		return nil, err
	}

	return x509.ParseCertificate(der)
}
