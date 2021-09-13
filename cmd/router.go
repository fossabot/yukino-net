package cmd

import (
	"fmt"
	"log"
	"math/rand"
	"time"

	"github.com/xpy123993/yukino-net/libraries/router"
	"github.com/xpy123993/yukino-net/libraries/router/keystore"
	"github.com/xpy123993/yukino-net/libraries/router/proto"
	"github.com/xpy123993/yukino-net/libraries/util"
)

type tokenAuthority struct {
	keyStore *keystore.KeyStore
}

func (auth *tokenAuthority) CheckPermission(frame *router.Frame, token []byte) bool {
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

func StartRouter(ConfigFile []string) error {
	rand.Seed(time.Now().UnixMicro())
	config, err := util.LoadClientConfig(ConfigFile)
	if err != nil {
		return err
	}

	keyStore, err := util.CreateOrLoadKeyStore(config.TokenFile)
	if err != nil {
		return fmt.Errorf("failed to initialize KeyStore: %v", err)
	}

	tlsConfig, err := util.LoadRouterTLSConfig(config)
	if err != nil {
		return fmt.Errorf("failed to load certificate: %v", err)
	}

	serviceRouter := router.NewRouter(router.RouterOption{
		TokenAuthority:            &tokenAuthority{keyStore: keyStore},
		DialConnectionTimeout:     3 * time.Second,
		ListenConnectionKeepAlive: 30 * time.Second,
		TLSConfig:                 tlsConfig,
		ChannelBufferBytes:        4096,
	})
	servingAddress := config.RouterAddress
	log.Printf("Starting listening on %s", servingAddress)
	return serviceRouter.ListenAndServe(servingAddress)
}
