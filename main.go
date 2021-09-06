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

const proxyChannel = "proxy"

func loadCertificateFromFlags() (*x509.CertPool, *tls.Certificate, error) {
	certificate, err := tls.X509KeyPair(crt, key)
	if err != nil {
		return nil, nil, fmt.Errorf("while loading certificate: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca)
	return pool, &certificate, nil
}

func routerMode() {
	caPool, certificate, err := loadCertificateFromFlags()
	if err != nil {
		log.Fatalf("error while loading certificate: %v", err)
	}
	router.ListenAndServeRouting(*servingAddress, caPool, certificate)
}

func proxyMode() {
	caPool, certificate, err := loadCertificateFromFlags()
	if err != nil {
		log.Fatalf("error while loading certificate: %v", err)
	}
	listener, err := router.ListenChannel(*servingAddress, proxyChannel, ServerName, caPool, certificate)
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
	caPool, certificate, err := loadCertificateFromFlags()
	if err != nil {
		log.Fatalf("error while loading certificate: %v", err)
	}
	listener, err := net.Listen("tcp", *proxyClientAddress)
	if err != nil {
		log.Fatalf("error while listening on proxy channel: %v", err)
	}
	for {
		client, err := listener.Accept()
		if err != nil {
			log.Println(err.Error())
			continue
		}
		go func(client net.Conn) {
			defer client.Close()
			conn, err := router.DialChannel(*servingAddress, proxyChannel, ServerName, caPool, certificate)
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
