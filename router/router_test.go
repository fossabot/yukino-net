package router_test

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"

	"github.com/xpy123993/router/router"
	"github.com/xpy123993/router/router/common"
	"github.com/xpy123993/router/router/proto"
)

func acceptAndEqual(listener net.Listener, message string) error {
	conn, err := listener.Accept()
	if err != nil {
		return fmt.Errorf("while accepting: %v", err)
	}
	defer conn.Close()

	buf := make([]byte, len(message))
	if _, err := io.ReadFull(conn, buf); err != nil {
		return err
	}
	if string(buf) != string(message) {
		return fmt.Errorf("content mismatch, expect %s, got %s", message, string(buf))
	}
	return nil
}

func dialAndSend(client *router.RouterClient, channel string, message []byte) error {
	conn, err := client.Dial(channel)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := conn.Write(message); err != nil {
		return err
	}
	return nil
}

type permissionDeniedAuthority struct{}
type myTokenAuthrority struct{}

func (*permissionDeniedAuthority) CheckPermission(*router.RouterFrame) bool { return false }
func (*myTokenAuthrority) CheckPermission(frame *router.RouterFrame) bool {
	switch frame.Type {
	case proto.Close:
		return true
	case proto.Nop:
		return true
	case proto.Bridge:
		return string(frame.Token) == "my-token"
	case proto.Listen:
		return string(frame.Token) == "my-token"
	case proto.Dial:
		return string(frame.Token) == "my-token"
	}
	return false
}

func TestPermissionDenied(t *testing.T) {
	t.Parallel()
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	option := router.DefaultRouterOption
	option.TokenAuthority = &permissionDeniedAuthority{}
	testRouter := router.NewRouter(option)

	go func() {
		testRouter.Serve(listener)
	}()

	_, err = router.NewListenerWithoutAuth(listener.Addr().String(), "test-channel")
	if err == nil {
		t.Error("expect an error here")
		return
	}

	testClient := router.NewClientWithoutAuth(listener.Addr().String())

	if err := dialAndSend(testClient, "test-channel", []byte{}); err == nil {
		t.Error("expect an error here")
		return
	}
	listener.Close()
}

func testSuite(t *testing.T, channel string, listener *router.RouterListener, client *router.RouterClient, router *router.Router) {
	pending := sync.WaitGroup{}

	testMessage := []byte("hello world")

	pending.Add(1)
	go func() {
		defer pending.Done()
		if err := acceptAndEqual(listener, string(testMessage)); err != nil {
			t.Error()
			return
		}
	}()

	if err := dialAndSend(client, channel, testMessage); err != nil {
		t.Fatal()
	}
	pending.Wait()
	listener.Close()
}

func tlstestSuite(t *testing.T, serverca *x509.CertPool, clientca *x509.CertPool, servercert *tls.Certificate, clientcert *tls.Certificate, success bool) {
	option := router.DefaultRouterOption
	option.TLSConfig = &tls.Config{
		RootCAs:      serverca,
		ClientCAs:    serverca,
		Certificates: []tls.Certificate{*servercert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}
	option.TokenAuthority = &myTokenAuthrority{}
	testRouter := router.NewRouter(option)
	listener, err := tls.Listen("tcp", ":0", option.TLSConfig)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	defer listener.Close()
	go func() {
		testRouter.Serve(listener)
	}()
	tlsConfig := tls.Config{
		RootCAs:      clientca,
		Certificates: []tls.Certificate{*clientcert},
		ServerName:   common.ServerName,
	}

	testListener, err := router.NewListener(listener.Addr().String(), []byte("my-token"), "test", &tlsConfig)
	if success == (err != nil) {
		t.Fatalf("unexpect result: %v", err)
	}
	testClient := router.NewClient(listener.Addr().String(), []byte("my-token"), &tlsConfig)
	if success {
		testSuite(t, "test", testListener, testClient, testRouter)
	}
}

func TestE2E(t *testing.T) {
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	defer listener.Close()
	testRouter := router.NewDefaultRouter()
	go func() {
		testRouter.Serve(listener)
	}()
	testListener, err := router.NewListenerWithoutAuth(listener.Addr().String(), "test")
	if err != nil {
		t.Fatalf("cannot create listener: %v", err)
	}
	testClient := router.NewClientWithoutAuth(listener.Addr().String())
	testSuite(t, "test", testListener, testClient, testRouter)
}

func TestE2EWithTLS(t *testing.T) {
	ca, priv, pub, err := common.GenerateCertSuite()
	if err != nil {
		t.Fatalf("cannot generate test certificates")
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca)
	cert, err := tls.X509KeyPair(pub, priv)
	if err != nil {
		t.Fatalf("invalid certificate received")
	}
	tlstestSuite(t, pool, pool, &cert, &cert, true)
}

func TestE2EWithTLSAuthFailed(t *testing.T) {
	serverCA, serverPriv, serverPub, err := common.GenerateCertSuite()
	if err != nil {
		t.Fatalf("cannot generate test certificates")
	}
	serverPool := x509.NewCertPool()
	serverPool.AppendCertsFromPEM(serverCA)
	serverCert, err := tls.X509KeyPair(serverPub, serverPriv)
	if err != nil {
		t.Fatalf("invalid certificate received")
	}
	clientCA, clientPriv, clientPub, err := common.GenerateCertSuite()
	if err != nil {
		t.Fatalf("cannot generate test certificates")
	}
	clientPool := x509.NewCertPool()
	clientPool.AppendCertsFromPEM(clientCA)
	clientCert, err := tls.X509KeyPair(clientPub, clientPriv)
	if err != nil {
		t.Fatalf("invalid certificate received %v", clientCert)
	}
	tlstestSuite(t, serverPool, clientPool, &serverCert, &clientCert, false)
	tlstestSuite(t, clientPool, clientPool, &serverCert, &clientCert, false)
	tlstestSuite(t, serverPool, clientPool, &clientCert, &clientCert, false)
	tlstestSuite(t, serverPool, serverPool, &serverCert, &clientCert, false)
}

func BenchmarkSmallConnection(b *testing.B) {
	b.SetParallelism(4)
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		b.Fatalf(err.Error())
	}
	defer listener.Close()

	pending := sync.WaitGroup{}
	testRouter := router.NewDefaultRouter()

	go func() {
		testRouter.Serve(listener)
	}()

	testListener, err := router.NewListenerWithoutAuth(listener.Addr().String(), "test-channel")
	if err != nil {
		b.Fatalf(err.Error())
	}

	testMessage := make([]byte, 32)

	b.ResetTimer()

	go func() {
		for i := 0; i < b.N; i++ {
			acceptAndEqual(testListener, string(testMessage))
		}
		pending.Done()
	}()

	testClient := router.NewClientWithoutAuth(listener.Addr().String())

	pending.Add(1)
	for i := 0; i < b.N; i++ {
		dialAndSend(testClient, "test-channel", testMessage)
	}
	pending.Wait()
}
