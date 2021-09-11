package cmd

import (
	"context"
	"io"
	"log"
	"net"
	"time"

	"github.com/xpy123993/yukino-net/libraries/router"
	"github.com/xpy123993/yukino-net/libraries/util"
)

func handleBridge(routerClient *router.RouterClient, channel string, client net.Conn) {
	defer client.Close()
	conn, err := routerClient.Dial(channel)
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

func Mount(ConfigFile, Channel, LocalAddr string) error {
	listener, err := net.Listen("tcp", LocalAddr)
	if err != nil {
		return err
	}
	routerClient, err := util.CreateClientFromConfig(ConfigFile)
	if err != nil {
		return err
	}
	log.Printf("Mounting channel `%s` on local address %s", Channel, LocalAddr)
	for {
		client, err := listener.Accept()
		if err != nil {
			continue
		}
		go handleBridge(routerClient, Channel, client)
	}
}
