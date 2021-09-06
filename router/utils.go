package router

import (
	"crypto/tls"
	"crypto/x509"
	"log"
	"net"
	"os"
)

// Default dialer creates a dialer with default settings.
var DefaultDialer = NewClient("", "local")

func createTCPConnection(network, address, servername string, pool *x509.CertPool, certificate *tls.Certificate) (net.Conn, error) {
	return tls.Dial(network, address, &tls.Config{
		RootCAs:      pool,
		ServerName:   servername,
		Certificates: []tls.Certificate{*certificate},
	})
}

// ListenAndServeRouting will create a router listening on `address`.
func ListenAndServeRouting(address string, pool *x509.CertPool, certificate *tls.Certificate) error {
	listener, err := tls.Listen("tcp", address, &tls.Config{
		RootCAs:      pool,
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		Certificates: []tls.Certificate{*certificate},
	})
	if err != nil {
		return err
	}
	hostRouter := NewRouter()
	log.Printf("listening on %s", listener.Addr().String())
	return hostRouter.Serve(listener)
}

// ListenChannel creates a channel listener listening on router network.
func ListenChannel(RouterAddress, Channel, RouterServerName string, CAPool *x509.CertPool, Certificate *tls.Certificate) (*RouterListener, error) {
	return NewRouterListenerWithConn(RouterAddress, Channel, func(nnetwork, naddress string) (net.Conn, error) {
		return createTCPConnection(nnetwork, naddress, RouterServerName, CAPool, Certificate)
	})
}

// DialChannel returns a connection to the channel in router network.
func DialChannel(RouterAddress, Channel, RouterServerName string, CAPool *x509.CertPool, Certificate *tls.Certificate) (net.Conn, error) {
	name, err := os.Hostname()
	if err != nil {
		name = "unknown sender"
	}
	DefaultDialer.channel = name
	conn, err := createTCPConnection("tcp", RouterAddress, RouterServerName, CAPool, Certificate)
	if err != nil {
		log.Printf("cannot process connection: %v", err)
		return nil, err
	}
	if err := DefaultDialer.DialWithConn(Channel, conn); err != nil {
		return nil, err
	}
	return conn, nil
}
