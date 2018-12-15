package main

import (
	"crypto/rsa"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/filipovi/simpleca/certificat"
	"github.com/filipovi/simpleca/key"
)

type simpleCA struct {
	pk  *rsa.PrivateKey
	c   *x509.Certificate
	ips []string
	dns []string
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func split(s string) (results []string) {
	if len(s) > 0 {
		return strings.Split(s, ",")
	}
	return nil
}

func check(pk *rsa.PrivateKey, c *x509.Certificate) error {
	isEqual, err := key.Equals(pk.Public(), c.PublicKey)
	if err != nil {
		return fmt.Errorf("comparing public keys: %s", err)
	}
	if !isEqual {
		return fmt.Errorf("public key in CA certificate doesn't match private key")
	}
	return nil
}

func newCA(ips, dns *string) (*simpleCA, error) {
	pk, err := key.New("ca-key.pem")
	if err != nil {
		return nil, err
	}
	c, err := certificat.New("ca-cert.pm", pk)
	if err != nil {
		return nil, err
	}
	if err = check(pk, c); err != nil {
		return nil, err
	}
	return &simpleCA{pk, c, split(*ips), split(*dns)}, nil
}

func (ca *simpleCA) generateSignedKeyAndCertificat(folder, cn string) error {
	if err := createFolder(folder); err != nil {
		return fmt.Errorf("Cannot create folder %s: %s", folder, err)
	}
	pk, err := key.New(fmt.Sprintf("%s/key.pem", folder))
	if err != nil {
		return err
	}
	c, err := certificat.NewSigned(fmt.Sprintf("%s/cert.pem", folder), cn, pk, ca.pk, ca.c, ca.ips, ca.dns)
	if err != nil {
		return err
	}
	if err = check(pk, c); err != nil {
		return err
	}
	return nil
}

func getCN(dns, ips string) string {
	if dns != "" {
		return split(dns)[0]
	}
	return split(ips)[0]
}

func getFolder(cn string) string {
	return strings.Replace(cn, "*", "_", -1)
}

func createFolder(folder string) error {
	err := os.Mkdir(folder, 0700)
	if err != nil && !os.IsExist(err) {
		return err
	}
	return nil
}

func run() error {
	dns := flag.String("dns", "", "Comma separated domain names")
	ips := flag.String("ips", "", "Comma separated IP addresses")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		fmt.Fprintf(os.Stderr, `
SimpleCA is useful in case you need to generate valid certificates for local development.
As soon as you can use a valid and routable domain name it is advisable to use a service
such as "Let’s Encrypt".
At its first execution, simpleCA will generate the keys and the root certificate.
The keys and certificates used by your web server will be created in a folder corresponding
to the first domain name or to the first IP address provided with the order.

`)
		flag.PrintDefaults()
	}
	flag.Parse()
	if *dns == "" && *ips == "" {
		flag.Usage()
		os.Exit(1)
	}

	ca, err := newCA(ips, dns)
	if err != nil {
		return err
	}

	cn := getCN(*dns, *ips)
	return ca.generateSignedKeyAndCertificat(getFolder(cn), cn)
}
