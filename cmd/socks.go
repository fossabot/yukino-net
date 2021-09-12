package cmd

import (
	"log"

	"github.com/armon/go-socks5"
	"github.com/xpy123993/yukino-net/libraries/util"
)

func StartSocks5Proxy(ConfigFile []string, Channel string) {
	listener, err := util.CreateListenerFromConfig(ConfigFile, Channel)
	if err != nil {
		log.Fatalf("error while listening on proxy channel: %v", err)
	}
	conf := socks5.Config{}
	server, err := socks5.New(&conf)
	if err != nil {
		log.Fatalf("failed to set up socks5: %v", err)
	}
	err = server.Serve(listener)
	log.Print(err)
}
