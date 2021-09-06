package common

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"time"
)

// ServerName is the server name of the certificate created by this tool.
const ServerName = "test"

func createCertificateSpec(isCA bool) *x509.Certificate {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		panic(err)
	}
	certificate := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization:  []string{"Company, INC."},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"San Francisco"},
			StreetAddress: []string{"Golden Gate Bridge"},
			PostalCode:    []string{"94016"},
		},
		NotBefore:          time.Now(),
		KeyUsage:           x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		NotAfter:           time.Now().AddDate(10, 0, 0),
		SignatureAlgorithm: x509.SHA512WithRSA,
	}
	if isCA {
		certificate.IsCA = true
		certificate.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
		certificate.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign
		certificate.BasicConstraintsValid = true
		certificate.DNSNames = []string{"test-authority"}
	} else {
		certificate.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
		certificate.DNSNames = []string{ServerName}
		certificate.SubjectKeyId = []byte{1, 2, 3, 4, 6}
		certificate.KeyUsage = x509.KeyUsageDigitalSignature
	}

	return &certificate
}

type certificateOption struct {
	GenerateCA bool
	KeyLength  int

	CACertificate x509.Certificate
	CAPriv        []byte
	CAPub         []byte
}

func generateCertificate(option certificateOption) ([]byte, []byte, *x509.Certificate, error) {
	cert := createCertificateSpec(option.GenerateCA)

	certPrivKey, err := rsa.GenerateKey(rand.Reader, option.KeyLength)
	if err != nil {
		return nil, nil, nil, err
	}

	var certBytes []byte
	if option.GenerateCA {
		certBytes, err = x509.CreateCertificate(rand.Reader, cert, cert, &certPrivKey.PublicKey, certPrivKey)
	} else {
		rawPriv, _ := pem.Decode(option.CAPriv)
		rsaPriv, _ := x509.ParsePKCS1PrivateKey(rawPriv.Bytes)
		certBytes, err = x509.CreateCertificate(rand.Reader, cert, &option.CACertificate, &certPrivKey.PublicKey, rsaPriv)
	}

	if err != nil {
		return nil, nil, nil, err
	}

	certPEM := new(bytes.Buffer)
	pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	certPrivKeyPEM := new(bytes.Buffer)
	pem.Encode(certPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(certPrivKey),
	})
	return certPrivKeyPEM.Bytes(), certPEM.Bytes(), cert, nil
}

// GenerateCertSuite returns a 10 days certificate.
// Returns CA, server private key, server public key, error in order.
func GenerateCertSuite() ([]byte, []byte, []byte, error) {
	priv, pub, cert, err := generateCertificate(
		certificateOption{
			GenerateCA: true,
			KeyLength:  2048,
		},
	)
	if err != nil {
		return nil, nil, nil, err
	}
	serverPriv, serverPub, _, err := generateCertificate(certificateOption{
		GenerateCA:    false,
		KeyLength:     2048,
		CACertificate: *cert,
		CAPriv:        priv,
		CAPub:         pub,
	})
	if err != nil {
		return nil, nil, nil, err
	}
	return pub, serverPriv, serverPub, nil
}
