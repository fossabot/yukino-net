package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"io/fs"
	"log"
	"math/rand"
	"os"
	"time"

	"github.com/xpy123993/router/libraries/router"
	"github.com/xpy123993/router/libraries/router/keystore"
	"github.com/xpy123993/router/libraries/router/proto"
)

var (
	configFile = flag.String("c", "config.json", "Server config file path.")
	config     serverConfig
)

type tokenAuthority struct {
	keyStore *keystore.KeyStore
}

type serverConfig struct {
	UseTLS        bool   `json:"tls" default:"false"`
	ListenAddress string `json:"router-address" default:":11020"`
	CaFile        string `json:"ca-file"`
	CertFile      string `json:"cert-file"`
	KeyFile       string `json:"key-file"`
	TokenFile     string `json:"token-file"`
}

func (auth *tokenAuthority) CheckPermission(frame *router.RouterFrame, token []byte) bool {
	if auth.keyStore == nil {
		return true
	}
	switch frame.Type {
	case proto.Dial:
		return auth.keyStore.CheckPermission(keystore.InvokeAction, frame.Channel, token)
	case proto.Bridge:
		return auth.keyStore.CheckPermission(keystore.ListenAction, frame.Channel, token)
	case proto.Listen:
		return auth.keyStore.CheckPermission(keystore.ListenAction, frame.Channel, token)
	}
	return false
}

func (auth *tokenAuthority) GetExpirationTime(key []byte) time.Time {
	if auth.keyStore == nil {
		return time.Now().Add(24 * time.Hour)
	}
	return auth.keyStore.GetExpireTime(key)
}

func saveConfig() error {
	fs, err := os.OpenFile(*configFile, 0755, fs.FileMode(os.O_CREATE))
	if err != nil {
		return err
	}
	defer fs.Close()
	encoder := json.NewEncoder(fs)
	encoder.SetIndent("", "  ")
	return encoder.Encode(config)
}

func readConfig() error {
	fs, err := os.Open(*configFile)
	if err != nil {
		return err
	}
	defer fs.Close()
	return json.NewDecoder(fs).Decode(&config)
}

func loadVariables() {
	if err := readConfig(); err != nil {
		if os.IsNotExist(err) {
			config.UseTLS = false
			config.ListenAddress = ":11010"
			if err := saveConfig(); err != nil {
				panic(err)
			} else {
				log.Printf("Config file %s does not exist, creating one", *configFile)
			}
		}
	}
	if len(config.ListenAddress) == 0 {
		log.Fatalf("invalid configuration: router-address is not specified")
	}
}

func loadTLSConfig() *tls.Config {
	if !config.UseTLS {
		return nil
	}
	certificate, err := tls.LoadX509KeyPair(config.CertFile, config.KeyFile)
	if err != nil {
		log.Fatalf("Error while loading TLS config: %v", err)
	}
	caBytes, err := os.ReadFile(config.CaFile)
	if err != nil {
		log.Fatalf("Error while loading TLS config: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caBytes) {
		log.Fatalf("Cannot parse CA certificate from %v", config.CaFile)
	}
	return &tls.Config{
		RootCAs:      pool,
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		Certificates: []tls.Certificate{certificate},
	}
}

func loadKeyStore() *keystore.KeyStore {
	tokenFile := config.TokenFile
	if len(tokenFile) == 0 {
		return nil
	}
	keyStore, err := keystore.LoadKeyStore(tokenFile)
	if err != nil {
		if os.IsNotExist(err) {
			keyStore := keystore.CreateKeyStore()
			if err := keyStore.Save(tokenFile); err != nil {
				log.Fatalf("cannot save created token file to disk: %v", err)
			}
		} else {
			log.Fatalf("cannot load specified keystore: %v", err)
		}
	}
	return keyStore
}

func main() {
	flag.Parse()
	loadVariables()
	rand.Seed(time.Now().UnixMicro())

	serviceRouter := router.NewRouter(router.RouterOption{
		TokenAuthority:            &tokenAuthority{keyStore: loadKeyStore()},
		DialConnectionTimeout:     3 * time.Second,
		ListenConnectionKeepAlive: 30 * time.Second,
		TLSConfig:                 loadTLSConfig(),
		ChannelBufferBytes:        4096,
	})
	servingAddress := config.ListenAddress
	log.Printf("Starting listening on %s", servingAddress)
	serviceRouter.ListenAndServe(servingAddress)
}
