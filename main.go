package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"github.com/armon/go-socks5"
	"github.com/xpy123993/router/router"

	_ "embed"
)

var (
	servingAddress     = flag.String("address", ":10110", "The address to serve")
	role               = flag.Int("role", 0, "0 - router, 1 - proxy server, 2 - proxy client")
	proxyClientAddress = flag.String("proxy-listen", ":10111", "The address to be forwarded.")
	token              = flag.String("token", "", "Token to be used to join the network")
)

const proxyChannel = "proxy"

func loadEmbededCertificates() (*x509.CertPool, *tls.Certificate, error) {
	certificate, err := tls.X509KeyPair(crt, key)
	if err != nil {
		return nil, nil, fmt.Errorf("while loading certificate: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca)
	return pool, &certificate, nil
}

type tokenAuthority struct{}

func (*tokenAuthority) CheckPermission(frame *router.RouterFrame) bool {
	return true
}

func routerMode() {
	caPool, certificate, err := loadEmbededCertificates()
	if err != nil {
		log.Fatalf("error while loading certificate: %v", err)
	}
	serviceRouter := router.NewRouter(router.RouterOption{
		TokenAuthority:            &tokenAuthority{},
		DialConnectionTimeout:     3 * time.Second,
		ListenConnectionKeepAlive: 30 * time.Second,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{*certificate},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			RootCAs:      caPool,
			ClientCAs:    caPool,
		},
	})
	serviceRouter.ListenAndServe(*servingAddress)
}

func proxyMode() {
	caPool, certificate, err := loadEmbededCertificates()
	if err != nil {
		log.Fatalf("error while loading certificate: %v", err)
	}
	var tokenBytes []byte
	if len(*token) > 0 {
		tokenBytes, err = hex.DecodeString(*token)
		if err != nil {
			log.Fatalf("cannot parse token")
		}
	}
	listener, err := router.NewListener(*servingAddress, tokenBytes, proxyChannel, &tls.Config{
		Certificates: []tls.Certificate{*certificate},
		RootCAs:      caPool,
		ServerName:   ServerName,
	})
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
	caPool, certificate, err := loadEmbededCertificates()
	if err != nil {
		log.Fatalf("error while loading certificate: %v", err)
	}
	listener, err := net.Listen("tcp", *proxyClientAddress)
	if err != nil {
		log.Fatalf("error while listening on proxy channel: %v", err)
	}
	var tokenBytes []byte
	if len(*token) > 0 {
		tokenBytes, err = hex.DecodeString(*token)
		if err != nil {
			log.Fatalf("cannot parse token")
		}
	}
	routerClient := router.NewClient(*servingAddress, tokenBytes, &tls.Config{
		RootCAs:      caPool,
		Certificates: []tls.Certificate{*certificate},
		ServerName:   ServerName,
	})
	for {
		client, err := listener.Accept()
		if err != nil {
			log.Println(err.Error())
			continue
		}
		go func(client net.Conn) {
			defer client.Close()
			conn, err := routerClient.Dial(proxyChannel)
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
