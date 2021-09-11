package main

import (
	"context"
	"flag"
	"io"
	"log"
	"net"
	"time"

	"github.com/xpy123993/router/libraries/router"
	"github.com/xpy123993/router/libraries/util"
)

var (
	localAddr  = flag.String("local-addr", ":10010", "If in proxy server mode, server will listen on specific address.")
	channel    = flag.String("channel", "proxy", "The channel to the proxy.")
	configFile = flag.String("config", "config.json", "The location of the config.")
)

func handleBridge(routerClient *router.RouterClient, client net.Conn) {
	defer client.Close()
	conn, err := routerClient.Dial(*channel)
	if err != nil {
		log.Print(err.Error())
		return
	}
	defer conn.Close()
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(3 * time.Second)
	}
	ctx, cancelFn := context.WithCancel(context.Background())
	go func() { io.Copy(client, conn); cancelFn() }()
	go func() { io.Copy(conn, client); cancelFn() }()
	<-ctx.Done()
}

func startProxy() {
	listener, err := net.Listen("tcp", *localAddr)
	if err != nil {
		log.Fatalf("error while listening on proxy channel: %v", err)
	}
	routerClient, err := util.CreateClientFromConfig(*configFile)
	if err != nil {
		log.Fatalf("failed to initialize client: %v", err)
	}
	log.Printf("Mounting channel `%s` on local address %s", *channel, *localAddr)
	for {
		client, err := listener.Accept()
		if err != nil {
			continue
		}
		go handleBridge(routerClient, client)
	}
}

func main() {
	flag.Parse()
	startProxy()
}
