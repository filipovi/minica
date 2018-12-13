package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math"
	"math/big"
	"net"
	"os"
	"strings"
	"time"
)

/**
1/ save minica cert + pem in ~/.minica
2/ option force
3/ add a function makeCertTemplate
4/ refactor the makeCert function
*/
func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func getMinicaPrivateKey(filename string) (*rsa.PrivateKey, error) {
	content, err := ioutil.ReadFile(filename)
	if err == nil {
		log.Printf("Read the Minica private key from %s", filename)
		return readPrivateKey(content)
	}
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	return makePrivateKey(filename)
}

func getMinicaCert(filename string, key *rsa.PrivateKey) (*x509.Certificate, error) {
	content, err := ioutil.ReadFile(filename)
	if err == nil {
		log.Printf("Read the Minica certificat from %s", filename)
		return readCert(content)
	}
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	return makeRootCert(key, filename)
}

func readPrivateKey(keyContents []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(keyContents)
	if block == nil {
		return nil, fmt.Errorf("no PEM found")
	}
	if block.Type != "RSA PRIVATE KEY" && block.Type != "ECDSA PRIVATE KEY" {
		return nil, fmt.Errorf("incorrect PEM type %s", block.Type)
	}

	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

func readCert(certContents []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certContents)
	if block == nil {
		return nil, fmt.Errorf("no PEM found")
	} else if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("incorrect PEM type %s", block.Type)
	}
	return x509.ParseCertificate(block.Bytes)
}

func makePrivateKey(filename string) (*rsa.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	der := x509.MarshalPKCS1PrivateKey(key)
	if err != nil {
		return nil, err
	}
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	err = pem.Encode(file, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: der,
	})
	if err != nil {
		return nil, err
	}

	log.Printf("Generate a new private key %s", filename)
	return key, nil
}

func makeRootCert(key crypto.Signer, filename string) (*x509.Certificate, error) {
	serial, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "minica root ca " + hex.EncodeToString(serial.Bytes()[:3]),
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

	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		return nil, err
	}
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	err = pem.Encode(file, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: der,
	})
	if err != nil {
		return nil, err
	}

	log.Printf("Generate a new root certificate %s", filename)
	return x509.ParseCertificate(der)
}

func parseIPs(ipAddresses []string) ([]net.IP, error) {
	var parsed []net.IP
	for _, s := range ipAddresses {
		p := net.ParseIP(s)
		if p == nil {
			return nil, fmt.Errorf("invalid IP address %s", s)
		}
		parsed = append(parsed, p)
	}
	return parsed, nil
}

func publicKeysEqual(a, b interface{}) (bool, error) {
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

func split(s string) (results []string) {
	if len(s) > 0 {
		return strings.Split(s, ",")
	}
	return nil
}

func run() error {
	minicaKeyFile := flag.String("ca-key", "minica-key.pem", "Root private key filename, PEM encoded.")
	minicaCertFile := flag.String("ca-cert", "minica.pem", "Root certificate filename, PEM encoded.")
	domains := flag.String("domains", "", "Comma separated domain names to include as Server Alternative Names.")
	ips := flag.String("ips", "", "Comma separated IP addresses to include as Server Alternative Names.")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		fmt.Fprintf(os.Stderr, `
Minica is a simple CA intended for use in situations where the CA operator
also operates each host where a certificate will be used. It automatically
generates both a key and a certificate when asked to produce a certificate.
It does not offer OCSP or CRL services. Minica is appropriate, for instance,
for generating certificates for RPC systems or microservices.

On first run, minica will generate a keypair and a root certificate in the
current directory, and will reuse that same keypair and root certificate
unless they are deleted.

On each run, minica will generate a new keypair and sign an end-entity (leaf)
certificate for that keypair. The certificate will contain a list of DNS names
and/or IP addresses from the command line flags. The key and certificate are
placed in a new directory whose name is chosen as the first domain name from
the certificate, or the first IP address if no domain names are present. It
will not overwrite existing keys or certificates.

`)
		flag.PrintDefaults()
	}
	flag.Parse()
	if *domains == "" && *ips == "" {
		flag.Usage()
		os.Exit(1)
	}

	var cn string
	if *domains != "" {
		cn = split(*domains)[0]
	} else {
		cn = split(*ips)[0]
	}

	folder := strings.Replace(cn, "*", "_", -1)

	minicaPrivateKey, err := getMinicaPrivateKey(*minicaKeyFile)
	if err != nil {
		return err
	}
	minicaCert, err := getMinicaCert(*minicaCertFile, minicaPrivateKey)
	if err != nil {
		return err
	}

	isEqual, err := publicKeysEqual(minicaPrivateKey.Public(), minicaCert.PublicKey)
	if err != nil {
		return fmt.Errorf("comparing public keys: %s", err)
	}
	if !isEqual {
		return fmt.Errorf("public key in CA certificate doesn't match private key")
	}

	err = os.Mkdir(folder, 0700)
	if err != nil && !os.IsExist(err) {
		return err
	}

	keyPem, err := makePrivateKey(fmt.Sprintf("%s/key.pem", folder))
	if err != nil {
		return err
	}
	parsedIPs, err := parseIPs(split(*ips))
	if err != nil {
		return err
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
	if err != nil {
		return err
	}

	template := &x509.Certificate{
		DNSNames:    split(*domains),
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
	der, err := x509.CreateCertificate(rand.Reader, template, minicaCert, keyPem.Public(), minicaPrivateKey)
	if err != nil {
		return err
	}

	log.Printf("Generate a new certificat %s", fmt.Sprintf("%s/cert.pem", folder))
	file, err := os.OpenFile(fmt.Sprintf("%s/cert.pem", folder), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer file.Close()
	err = pem.Encode(file, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: der,
	})
	if err != nil {
		return err
	}
	_, err = x509.ParseCertificate(der)

	return err
}
