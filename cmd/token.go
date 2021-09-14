package cmd

import (
	"archive/zip"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path"
	"time"

	"github.com/xpy123993/yukino-net/libraries/common"
	"github.com/xpy123993/yukino-net/libraries/router/keystore"
	"github.com/xpy123993/yukino-net/libraries/util"
)

func calculateCertificateSignature(cert *tls.Certificate) (string, error) {
	certificate, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return "", fmt.Errorf("failed to parse the certificate: %v", err)
	}
	return keystore.HashKey(certificate.Signature), nil
}

func cmdGenerateCA(CertName string, OutputFolder string) error {
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

func loadCA(CAFolder string) ([]byte, []byte, *x509.Certificate, error) {
	caTLSCert, err := tls.LoadX509KeyPair(path.Join(CAFolder, "ca.crt"), path.Join(CAFolder, "ca.key"))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to load CA certificates: %v", err)
	}
	caCert, err := x509.ParseCertificate(caTLSCert.Certificate[0])
	if err != nil {
		return nil, nil, nil, err
	}
	caPub, err := os.ReadFile(path.Join(CAFolder, "ca.crt"))
	if err != nil {
		return nil, nil, nil, err
	}
	caPriv, err := os.ReadFile(path.Join(CAFolder, "ca.key"))
	if err != nil {
		return nil, nil, nil, err
	}
	return caPriv, caPub, caCert, nil
}

func cmdGenerateCertificate(CertName string, DNSName string, CAFolder string, OutputFolder string) error {
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

	caPriv, caPub, caCert, err := loadCA(CAFolder)
	if err != nil {
		return err
	}
	priv, pub, _, err := common.GenerateCertificate(common.GenCertOption{
		CertName:      CertName,
		DNSName:       DNSName,
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

func cmdAddCertPermission(KeyFile, CertFile, TokenFile string) error {
	cert, err := tls.LoadX509KeyPair(CertFile, KeyFile)
	if err != nil {
		return fmt.Errorf("failed to load the certificate: %v", err)
	}
	certificate, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return fmt.Errorf("failed to parse the certificate: %v", err)
	}

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

func batchWrite(dataMap map[string][]byte, writer *zip.Writer) error {
	for filename, data := range dataMap {
		f, err := writer.Create(filename)
		if err != nil {
			return err
		}
		if n, err := f.Write(data); err != nil {
			return err
		} else if n != len(data) {
			return fmt.Errorf("not fully save")
		}
	}
	return nil
}

func generateConfigZIP(RouterAddress string, CAFolder string, ServerDNS string, TokenFile string, ConfigFile string) error {
	caPriv, caPub, caCert, err := loadCA(CAFolder)
	if err != nil {
		return err
	}
	priv, pub, _, err := common.GenerateCertificate(common.GenCertOption{
		CertName:      ServerDNS,
		DNSName:       ServerDNS,
		KeyLength:     4096,
		IsCA:          false,
		CACertificate: *caCert,
		CAPriv:        caPriv,
		CAPub:         caPub,
	})
	if err != nil {
		return fmt.Errorf("error while generate certificate: %v", err)
	}
	cert, err := tls.X509KeyPair(pub, priv)
	if err != nil {
		return err
	}
	signature, err := calculateCertificateSignature(&cert)
	if err != nil {
		return err
	}
	log.Printf("Cert signature: %s", signature)
	config := util.ClientConfig{
		RouterAddress:      RouterAddress,
		ServerNameOverride: RouterAddress,
		EnableTLS:          true,
		TokenFile:          TokenFile,
		KeyFile:            "cert.key",
		CertFile:           "cert.crt",
		CaCert:             "ca.crt",
	}
	configData, err := json.MarshalIndent(config, "", "    ")
	if err != nil {
		return fmt.Errorf("error while creating config: %v", err)
	}
	buf := new(bytes.Buffer)
	w := zip.NewWriter(buf)
	w.SetComment("This file contains a configuration set for yukino-net. Cert signature: " + signature)
	if err := batchWrite(map[string][]byte{
		"cert.key":    priv,
		"cert.crt":    pub,
		"ca.crt":      caPub,
		"config.json": configData,
	}, w); err != nil {
		return fmt.Errorf("error while preparing config: %v", err)
	}
	w.Close()
	return os.WriteFile(ConfigFile, buf.Bytes(), 0777)
}
