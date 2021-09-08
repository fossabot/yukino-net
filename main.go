package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"log"
	"os"
	"time"

	"github.com/spf13/viper"
	"github.com/xpy123993/router/router"
	"github.com/xpy123993/router/router/proto"
	"github.com/xpy123993/router/token"
)

type tokenAuthority struct {
	keyStore *token.KeyStore
}

func (auth *tokenAuthority) CheckPermission(frame *router.RouterFrame) bool {
	if auth.keyStore == nil {
		return true
	}
	switch frame.Type {
	case proto.Dial:
		return auth.keyStore.CheckPermission(token.InvokeAction, frame.Channel, frame.Token)
	case proto.Bridge:
		return auth.keyStore.CheckPermission(token.ListenAction, frame.Channel, frame.Token)
	case proto.Listen:
		return auth.keyStore.CheckPermission(token.ListenAction, frame.Channel, frame.Token)
	}
	return false
}

func (auth *tokenAuthority) GetExpirationTime(key []byte) time.Time {
	if auth.keyStore == nil {
		return time.Now().Add(24 * time.Hour)
	}
	return auth.keyStore.GetExpireTime(key)
}

func loadVariables() {
	viper.SetConfigName("config")
	viper.SetConfigType("toml")
	viper.AddConfigPath(".")
	viper.SetDefault("use-tls", "false")
	viper.SetDefault("listen-address", ":11020")

	viper.SetDefault("ca-cert", "")
	viper.SetDefault("server-key", "")
	viper.SetDefault("server-cert", "")
	viper.SetDefault("token-file", "")

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			viper.SafeWriteConfig()
		}
	}
}

func loadTLSConfig() *tls.Config {
	if !viper.GetBool("use-tls") {
		return nil
	}
	certificate, err := tls.LoadX509KeyPair(viper.GetString("server-cert"), viper.GetString("server-key"))
	if err != nil {
		log.Fatalf("Error while loading TLS config: %v", err)
	}
	caBytes, err := os.ReadFile(viper.GetString("ca-cert"))
	if err != nil {
		log.Fatalf("Error while loading TLS config: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caBytes) {
		log.Fatalf("Cannot parse CA certificate from %v", viper.GetString("ca-cert"))
	}
	return &tls.Config{
		RootCAs:      pool,
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		Certificates: []tls.Certificate{certificate},
	}
}

func loadKeyStore() *token.KeyStore {
	tokenFile := viper.GetString("token-file")
	if len(tokenFile) == 0 {
		return nil
	}
	keyStore, err := token.LoadKeyStore(tokenFile)
	if err != nil {
		if os.IsNotExist(err) {
			keyStore := token.CreateKeyStore()
			log.Printf("Generated a temporary key: %s", keyStore.GenerateKeyAndRegister("temp-key", []token.ACLRule{
				{
					ListenControl: token.Allow,
					InvokeControl: token.Allow,
					ChannelRegexp: ".*",
				}}, 5*time.Minute))
			log.Println("This key will expire in 5 minutes.")
			if err := keyStore.Save(tokenFile); err != nil {
				log.Fatalf("cannot save token: %v", err)
			}
		} else {
			log.Fatalf("Cannot load specified keystore: %v", err)
		}
	}
	return keyStore
}

func routerMode() {
	loadVariables()

	serviceRouter := router.NewRouter(router.RouterOption{
		TokenAuthority:            &tokenAuthority{keyStore: loadKeyStore()},
		DialConnectionTimeout:     3 * time.Second,
		ListenConnectionKeepAlive: 30 * time.Second,
		TLSConfig:                 loadTLSConfig(),
	})
	servingAddress := viper.GetString("listen-address")
	log.Printf("Starting listening on %s", servingAddress)
	serviceRouter.ListenAndServe(servingAddress)
}

func main() {
	flag.Parse()
	routerMode()
}
