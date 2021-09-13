package util

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/xpy123993/yukino-net/libraries/router"
	"github.com/xpy123993/yukino-net/libraries/router/keystore"
)

// ClientConfig stores the configuration to connect to the Router network.
type ClientConfig struct {
	// RouterAddress is the network address of the Router.
	RouterAddress string `json:"router-address"`

	// EnableTLS -- If true, `CaCert`, `ClientCert` and `ClientKey` will be used to communicate with the Router. Must be the same to the router.
	EnableTLS bool `json:"tls"`

	// CaCert stores the filename to load a PEM CA cert. Used for server authentication.
	CaCert string `json:"ca-file"`

	// ServerNameOverride overrides the server name used for the client to authenticate the Router if not empty.
	ServerNameOverride string `json:"server-name"`

	// CertFile stores the filename to the client's cert file in PEM format, used for providing an identity to the server.
	CertFile string `json:"cert-file"`

	// KeyFile stores the filename to the client's key file in PEM format.
	KeyFile string `json:"key-file"`

	// TokenFile provides the Router extra ACL control in application layer.
	TokenFile string `json:"token-file"`
}

func parseCAAndCertificate(config *ClientConfig) (*x509.CertPool, *tls.Certificate, error) {
	caPool := x509.NewCertPool()
	data, err := os.ReadFile(config.CaCert)
	if err != nil {
		return nil, nil, err
	}
	if !caPool.AppendCertsFromPEM(data) {
		return nil, nil, fmt.Errorf("cannot insert %s into cert pool", config.CaCert)
	}

	certificate, err := tls.LoadX509KeyPair(config.CertFile, config.KeyFile)
	if err != nil {
		return nil, nil, err
	}
	return caPool, &certificate, err
}

func createClientTLSConfig(config *ClientConfig) (*tls.Config, error) {
	if !config.EnableTLS {
		return nil, nil
	}
	caPool, certificate, err := parseCAAndCertificate(config)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{*certificate},
		RootCAs:      caPool,
		ServerName:   config.ServerNameOverride,
	}, nil
}

// LoadRouterTLSConfig returns the tls config used by a router.
// If `EnableTLS` is false, a nil will be returned.
func LoadRouterTLSConfig(config *ClientConfig) (*tls.Config, error) {
	if !config.EnableTLS {
		return nil, nil
	}
	caPool, certificate, err := parseCAAndCertificate(config)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		RootCAs:      caPool,
		ClientCAs:    caPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		Certificates: []tls.Certificate{*certificate},
	}, nil
}

// LoadClientConfig loads client configuration from `ConfigFile`, returns any error encountered.
func LoadClientConfig(ConfigFile []string) (*ClientConfig, error) {
	var data []byte
	var err error
	for _, config := range ConfigFile {
		data, err = os.ReadFile(config)
		if err == nil {
			log.Printf("Config loaded from %s", config)
			break
		}
	}
	if err != nil {
		return nil, err
	}
	clientConfig := ClientConfig{}
	if err := json.Unmarshal(data, &clientConfig); err != nil {
		return nil, err
	}
	return &clientConfig, nil
}

// LoadClientTLSConfig returns only the TLSConfig part from `ConfigFile`.
func LoadClientTLSConfig(ConfigFile []string) (*tls.Config, error) {
	rawConfig, err := LoadClientConfig(ConfigFile)
	if err != nil {
		return nil, err
	}
	return createClientTLSConfig(rawConfig)
}

// CreateListenerFromConfig creates a listener on `ListenChannel` from `ConfigFile`.
func CreateListenerFromConfig(ConfigFile []string, ListenChannel string) (*router.Listener, error) {
	config, err := LoadClientConfig(ConfigFile)
	if err != nil {
		return nil, err
	}
	tlsConfig, err := createClientTLSConfig(config)
	if err != nil {
		return nil, fmt.Errorf("error while loading certificate: %v", err)
	}
	return router.NewListener(config.RouterAddress, ListenChannel, tlsConfig)
}

// CreateClientFromConfig creates a client from `ConfigFile`.
func CreateClientFromConfig(ConfigFile []string) (*router.Client, error) {
	config, err := LoadClientConfig(ConfigFile)
	if err != nil {
		return nil, err
	}
	tlsConfig, err := createClientTLSConfig(config)
	if err != nil {
		return nil, fmt.Errorf("error while parsing token: %v", err)
	}
	return router.NewClient(config.RouterAddress, tlsConfig), nil
}

// CreateOrLoadKeyStore loads a KeyStore from `tokenFile`. If this file does not exist, a new config will be generated.
func CreateOrLoadKeyStore(tokenFile string) (*keystore.KeyStore, error) {
	if len(tokenFile) == 0 {
		return nil, nil
	}
	keyStore, err := keystore.LoadKeyStore(tokenFile)
	if err != nil {
		if os.IsNotExist(err) {
			keyStore := keystore.CreateKeyStore()
			if err := keyStore.Save(tokenFile); err != nil {
				return nil, err
			}
		} else {
			return nil, err
		}
	}
	return keyStore, nil
}
