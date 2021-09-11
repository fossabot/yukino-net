package main

import (
	"flag"
	"log"

	"github.com/armon/go-socks5"
	"github.com/xpy123993/router/libraries/util"
)

var (
	channel    = flag.String("channel", "proxy", "The channel to the proxy.")
	configFile = flag.String("config", "config.json", "The location of the config.")
)

func proxyMode() {
	listener, err := util.CreateListenerFromConfig(*configFile, *channel)
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

func main() {
	flag.Parse()
	proxyMode()
}
