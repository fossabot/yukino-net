package cmd

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"os"
	"path"
	"time"

	"github.com/xpy123993/yukino-net/libraries/common"
	"github.com/xpy123993/yukino-net/libraries/router/keystore"
	"github.com/xpy123993/yukino-net/libraries/util"
)

func GenerateCA(CertName string, OutputFolder string) error {
	if stats, err := os.Stat(OutputFolder); err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("error while probing output folder: %v", err)
		}
		if err := os.MkdirAll(OutputFolder, 0744); err != nil {
			return fmt.Errorf("error while creating output directory: %v", err)
		}
	} else if !stats.IsDir() {
		return fmt.Errorf("invalid argument: expect to take a folder name, got a file")
	}
	if _, err := os.Stat(path.Join(OutputFolder, "ca.key")); err == nil {
		return fmt.Errorf("error: ca.key already exists, please remove it manually")
	}
	priv, pub, _, err := common.GenerateCertificate(common.GenCertOption{
		CertName:  CertName,
		KeyLength: 4096,
		IsCA:      true,
	})
	if err != nil {
		return err
	}
	if err := os.WriteFile(path.Join(OutputFolder, "ca.key"), priv, 0744); err != nil {
		return err
	}
	log.Printf("Created: %s", path.Join(OutputFolder, "ca.key"))
	if err := os.WriteFile(path.Join(OutputFolder, "ca.crt"), pub, 0744); err != nil {
		return err
	}
	log.Printf("Created: %s", path.Join(OutputFolder, "ca.crt"))
	return nil
}

func GenerateCertificate(CertName string, DNSName string, CAFolder string, OutputFolder string) error {
	if stats, err := os.Stat(OutputFolder); err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("error while probing output folder: %v", err)
		}
		if err := os.MkdirAll(OutputFolder, 0744); err != nil {
			return fmt.Errorf("error while creating output directory: %v", err)
		}
	} else if !stats.IsDir() {
		return fmt.Errorf("invalid argument: expect to take a folder name, got a file")
	}
	if _, err := os.Stat(path.Join(OutputFolder, CertName+".key")); err == nil {
		return fmt.Errorf("error: ca.key already exists, please remove it manually")
	}

	caTLSCert, err := tls.LoadX509KeyPair(path.Join(CAFolder, "ca.crt"), path.Join(CAFolder, "ca.key"))
	if err != nil {
		return fmt.Errorf("failed to load CA certificates: %v", err)
	}
	caCert, err := x509.ParseCertificate(caTLSCert.Certificate[0])
	if err != nil {
		return err
	}
	caPub, err := os.ReadFile(path.Join(CAFolder, "ca.crt"))
	if err != nil {
		return err
	}
	caPriv, err := os.ReadFile(path.Join(CAFolder, "ca.key"))
	if err != nil {
		return err
	}
	priv, pub, _, err := common.GenerateCertificate(common.GenCertOption{
		CertName:      CertName,
		DnsName:       DNSName,
		KeyLength:     4096,
		IsCA:          false,
		CACertificate: *caCert,
		CAPriv:        caPriv,
		CAPub:         caPub,
	})
	if err != nil {
		return err
	}
	if err := os.WriteFile(path.Join(OutputFolder, CertName+".key"), priv, 0744); err != nil {
		return err
	}
	log.Printf("Created: %s", path.Join(OutputFolder, CertName+".key"))
	if err := os.WriteFile(path.Join(OutputFolder, CertName+".crt"), pub, 0744); err != nil {
		return err
	}
	log.Printf("Created: %s", path.Join(OutputFolder, CertName+".crt"))
	return nil
}

func AddCertPermission(KeyFile, CertFile, TokenFile string) error {
	cert, err := tls.LoadX509KeyPair(CertFile, KeyFile)
	if err != nil {
		return fmt.Errorf("failed to load the certificate: %v", err)
	}
	certificate, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return fmt.Errorf("failed to parse the certificate: %v", err)
	}
	log.Printf("Token is: %s", keystore.HashKey(certificate.Signature))

	keyStore, err := util.CreateOrLoadKeyStore(TokenFile)
	if err != nil {
		return fmt.Errorf("failed to initialize KeyStore: %v", err)
	}

	rule := keystore.ACLRule{}

	fmt.Print("Channel Regular Expression to apply the policy: ")
	fmt.Scanln(&rule.ChannelRegexp)

	var resp string
	fmt.Print("Allow Listen? (y/n): ")
	fmt.Scanln(&resp)
	if resp == "y" {
		rule.ListenControl = keystore.Allow
	} else if resp != "n" {
		rule.ListenControl = keystore.Deny
		log.Printf("Cannot recongnize %s, set to deny", resp)
	}
	fmt.Print("Allow Invoke? (y/n): ")
	fmt.Scanln(&resp)
	if resp == "y" {
		rule.InvokeControl = keystore.Allow
	} else if resp != "n" {
		rule.ListenControl = keystore.Deny
		log.Printf("Cannot recongnize %s, set to deny", resp)
	}

	sessionKey := keyStore.GetSessionKey(certificate.Signature)
	if sessionKey == nil {
		sessionKey = &keystore.SessionKey{
			ID:          certificate.Subject.CommonName,
			Expire:      certificate.NotAfter,
			Description: "ACL rules for " + certificate.Subject.CommonName + " generated at " + time.Now().Format(time.RFC3339),
		}
	}
	sessionKey.Rules = append(sessionKey.Rules, rule)
	keyStore.UpdateKey(certificate.Signature, *sessionKey)
	return keyStore.Save(TokenFile)
}
