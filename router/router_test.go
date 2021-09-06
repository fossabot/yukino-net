package router_test

import (
	"fmt"
	"io"
	"net"
	"sync"
	"testing"

	"github.com/xpy123993/router/router"
)

func acceptAndEqual(listener net.Listener, message string) error {
	conn, err := listener.Accept()
	if err != nil {
		return err
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
	conn, err := client.Dial("test-channel")
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := conn.Write(message); err != nil {
		return err
	}
	return nil
}

func TestE2E(t *testing.T) {
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	pending := sync.WaitGroup{}
	testRouter := router.NewRouter()

	pending.Add(1)
	go func() {
		testRouter.Serve(listener)
		pending.Done()
	}()

	testListener, err := router.NewRouterListener(listener.Addr().String(), "test-channel")
	if err != nil {
		t.Error(err)
		return
	}

	testMessage := []byte("hello world")

	pending.Add(1)
	go func() {
		defer pending.Done()
		if err := acceptAndEqual(testListener, string(testMessage)); err != nil {
			t.Error(err)
		}
		if err := acceptAndEqual(testListener, string(testMessage)); err != nil {
			t.Error(err)
		}
	}()

	testClient := router.NewClient(listener.Addr().String(), "sender-channel")

	if err := dialAndSend(testClient, "test-channel", testMessage); err != nil {
		t.Error(err)
	}

	if err := dialAndSend(testClient, "test-channel", testMessage); err != nil {
		t.Error(err)
	}

	testListener.Close()

	if err := dialAndSend(testClient, "test-channel", testMessage); err == nil {
		t.Error("expect an error here")
	}

	listener.Close()
	pending.Wait()
}

func BenchmarkSmallConnection(b *testing.B) {
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		b.Fatalf(err.Error())
	}
	defer listener.Close()

	pending := sync.WaitGroup{}
	testRouter := router.NewRouter()

	go func() {
		testRouter.Serve(listener)
	}()

	testListener, err := router.NewRouterListener(listener.Addr().String(), "test-channel")
	if err != nil {
		b.Fatalf(err.Error())
	}

	testMessage := make([]byte, 4096)

	go func() {
		for i := 0; i < b.N; i++ {
			acceptAndEqual(testListener, string(testMessage))
			pending.Done()
		}
	}()

	testClient := router.NewClient(listener.Addr().String(), "sender-channel")

	for i := 0; i < b.N; i++ {
		pending.Add(1)
		dialAndSend(testClient, "test-channel", testMessage)
	}
	pending.Wait()
}
