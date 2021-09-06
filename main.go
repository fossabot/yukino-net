package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"log"
	"net"

	"github.com/armon/go-socks5"
	"github.com/xpy123993/router/router"

	_ "embed"
)

var (
	servingAddress     = flag.String("address", ":10110", "The address to serve")
	role               = flag.Int("role", 0, "0 - router, 1 - proxy server, 2 - proxy client")
	proxyClientAddress = flag.String("proxy-listen", ":10111", "The address to be forwarded.")
)

func loadCertificateFromFlags() (*x509.CertPool, *tls.Certificate, error) {
	certificate, err := tls.X509KeyPair(crt, key)
	if err != nil {
		return nil, nil, fmt.Errorf("while loading certificate: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca)
	return pool, &certificate, nil
}

func createListener() (net.Listener, error) {
	pool, certificate, err := loadCertificateFromFlags()
	if err != nil {
		return nil, err
	}
	return tls.Listen("tcp", *servingAddress, &tls.Config{
		RootCAs:      pool,
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		Certificates: []tls.Certificate{*certificate},
	})
}

func createTCPConnection(network, address string) (net.Conn, error) {
	pool, certificate, err := loadCertificateFromFlags()
	if err != nil {
		return nil, err
	}
	return tls.Dial(network, address, &tls.Config{
		RootCAs:      pool,
		ServerName:   ServerName,
		Certificates: []tls.Certificate{*certificate},
	})
}

func routerMode() {
	listener, err := createListener()
	if err != nil {
		log.Fatalf("error while start listening: %v", err)
	}
	hostRouter := router.NewRouter()
	log.Printf("listening on %s", listener.Addr().String())
	hostRouter.Serve(listener)
}

func proxyMode() {
	listener, err := router.NewRouterListenerWithConn(*servingAddress, "proxy", createTCPConnection)
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

func proxyClientMode() {
	listener, err := net.Listen("tcp", *proxyClientAddress)
	if err != nil {
		log.Fatalf("error while listening on proxy channel: %v", err)
	}
	targetClient := router.NewClient(*servingAddress, "client")
	for {
		client, err := listener.Accept()
		if err != nil {
			log.Println(err.Error())
			continue
		}
		go func(client net.Conn) {
			defer client.Close()
			conn, err := createTCPConnection("tcp", *servingAddress)
			if err != nil {
				log.Printf("cannot process connection: %v", err)
				return
			}
			err = targetClient.DialWithConn("proxy", conn)
			if err != nil {
				log.Println(err.Error())
				return
			}
			ctx, cancelFn := context.WithCancel(context.Background())
			go func() { io.Copy(client, conn); cancelFn() }()
			go func() { io.Copy(conn, client); cancelFn() }()
			<-ctx.Done()
		}(client)
	}
}

func main() {
	flag.Parse()
	log.SetFlags(log.Default().Flags() | log.Lshortfile)
	switch *role {
	case 0:
		routerMode()
	case 1:
		proxyMode()
	case 2:
		proxyClientMode()
	}
}
