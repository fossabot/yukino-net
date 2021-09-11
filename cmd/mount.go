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

func bridge(peerA, peerB net.Conn) {
	ctx, cancelFn := context.WithCancel(context.Background())
	go func() { io.Copy(peerA, peerB); cancelFn() }()
	go func() { io.Copy(peerB, peerA); cancelFn() }()
	<-ctx.Done()
}

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
	bridge(conn, client)
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

func MountRemote(ConfigFile, Channel, RemoteAddr string) error {
	listener, err := util.CreateListenerFromConfig(ConfigFile, Channel)
	if err != nil {
		return err
	}
	log.Printf("Mounting channel `%s` on remote address %s", Channel, RemoteAddr)
	for {
		client, err := listener.Accept()
		if err != nil {
			continue
		}
		go func(conn net.Conn) {
			defer conn.Close()
			peer, err := net.Dial("tcp", RemoteAddr)
			if err != nil {
				return
			}
			defer peer.Close()
			bridge(conn, peer)
		}(client)
	}
}
