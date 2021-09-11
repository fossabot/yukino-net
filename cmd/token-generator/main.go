package main

import (
	"crypto/tls"
	"crypto/x509"
	"log"
	"os"

	"github.com/xpy123993/router/libraries/router/keystore"
)

func main() {
	if len(os.Args) < 3 {
		log.Printf("Usage: token-generator <cert file> <key file>\nThis tool will generate the corresponding token that can be used in token configs.")
		return
	}
	cert, err := tls.LoadX509KeyPair(os.Args[1], os.Args[2])
	if err != nil {
		log.Fatalf("failed to load the certificate: %v", err)
	}
	certificate, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		log.Fatalf("failed to parse the certificate: %v", err)
	}
	log.Printf("Token is: %s", keystore.HashKey(certificate.Signature))
}
