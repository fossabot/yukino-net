package utils

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	"github.com/xpy123993/router/router"
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

	// ClientCert stores the filename to the client's cert file in PEM format, used for providing an identity to the server.
	ClientCert string `json:"cert-file"`

	// ClientKey stores the filename to the client's key file in PEM format.
	ClientKey string `json:"key-file"`

	// Token stores the API key for authentication.
	Token string `json:"token"`
}

func createTLSConfig(config *ClientConfig) (*tls.Config, error) {
	if !config.EnableTLS {
		return nil, nil
	}
	caPool := x509.NewCertPool()
	if data, err := os.ReadFile(config.CaCert); err != nil {
		return nil, err
	} else {
		caPool.AppendCertsFromPEM(data)
	}
	certificate, err := tls.LoadX509KeyPair(config.ClientCert, config.ClientKey)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{certificate},
		RootCAs:      caPool,
		ServerName:   config.ServerNameOverride,
	}, nil
}

func parseAuthParams(config *ClientConfig) (*tls.Config, []byte, error) {
	tlsConfig, err := createTLSConfig(config)
	if err != nil {
		return nil, nil, err
	}
	if len(config.Token) == 0 {
		return tlsConfig, nil, nil
	}
	token, err := base64.RawStdEncoding.DecodeString(config.Token)
	return tlsConfig, token, err
}

// LoadClientConfig loads client configuration from `ConfigFile`, returns any error encountered.
func LoadClientConfig(ConfigFile string) (*ClientConfig, error) {
	data, err := os.ReadFile(ConfigFile)
	if err != nil {
		return nil, err
	}
	clientConfig := ClientConfig{}
	if err := json.Unmarshal(data, &clientConfig); err != nil {
		return nil, err
	}
	return &clientConfig, nil
}

// CreateListenerFromConfig creates a listener on `ListenChannel` from `ConfigFile`.
func CreateListenerFromConfig(ConfigFile string, ListenChannel string) (*router.RouterListener, error) {
	config, err := LoadClientConfig(ConfigFile)
	if err != nil {
		return nil, err
	}
	tlsConfig, token, err := parseAuthParams(config)
	if err != nil {
		return nil, fmt.Errorf("error while parsing token: %v", err)
	}
	return router.NewListener(config.RouterAddress, token, ListenChannel, tlsConfig)
}

// CreateClientFromConfig creates a client from `ConfigFile`.
func CreateClientFromConfig(ConfigFile string) (*router.RouterClient, error) {
	config, err := LoadClientConfig(ConfigFile)
	if err != nil {
		return nil, err
	}
	tlsConfig, token, err := parseAuthParams(config)
	if err != nil {
		return nil, fmt.Errorf("error while parsing token: %v", err)
	}
	return router.NewClient(config.RouterAddress, token, tlsConfig), nil
}
