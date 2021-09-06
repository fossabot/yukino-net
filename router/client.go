package router

import (
	"crypto/tls"
	"encoding/gob"
	"fmt"
	"io"
	"log"
	"net"
)

// RouterClient implements a Dial method to join the Router network.
type RouterClient struct {
	routerAddress string
	channel       string
}

// NewClient creates a RouterClient structure.
func NewClient(RouterAddress string, Channel string) *RouterClient {
	return &RouterClient{
		routerAddress: RouterAddress,
		channel:       Channel,
	}
}

// DialWithConn initiates dial protocol from existing connection.
// The connection can be from a tls.
func (client *RouterClient) DialWithConn(TargetChannel string, Conn net.Conn) error {
	if err := gob.NewEncoder(Conn).Encode(RouterFrame{
		Type:    Dial,
		Channel: TargetChannel,
	}); err != nil {
		return err
	}
	frame := RouterFrame{}
	if err := gob.NewDecoder(Conn).Decode(&frame); err != nil {
		return err
	}
	return nil
}

// Dial initiaites a dial request into the Route network.
func (client *RouterClient) Dial(TargetChannel string) (net.Conn, error) {
	conn, err := net.Dial("tcp", client.routerAddress)
	if err != nil {
		return nil, err
	}
	if err := client.DialWithConn(TargetChannel, conn); err != nil {
		return nil, err
	}
	return conn, nil
}

// RouterListener implements a net.Listener interface on Router network.
type RouterListener struct {
	routerAddress  string
	channel        string
	controlConn    net.Conn
	connInitialier func(string, string) (net.Conn, error)

	decoder *gob.Decoder
}

// RouterAddress represents an address in Router network.
type RouterAddress struct {
	Channel string
}

// Network returns the network type.
func (*RouterAddress) Network() string {
	return "Yukino"
}

// String return the channel name of this address.
func (address *RouterAddress) String() string {
	return address.Channel
}

// NewRouterListenerWithConn creates a RouterListener structure.
// Conn here can be a just initialized connectiono from TLS.
func NewRouterListenerWithConn(
	RouterAddress string, Channel string, ConnInitialier func(string, string) (net.Conn, error)) (*RouterListener, error) {
	conn, err := ConnInitialier("tcp", RouterAddress)
	if tlsConn, ok := conn.(*tls.Conn); ok {
		log.Printf("connection is built above TLS")
		log.Printf("CipherSuite: %s", tls.CipherSuiteName(tlsConn.ConnectionState().CipherSuite))
	}
	if err != nil {
		return nil, err
	}
	if err := gob.NewEncoder(conn).Encode(RouterFrame{
		Type:    Listen,
		Channel: Channel,
	}); err != nil {
		return nil, err
	}
	frame := RouterFrame{}
	decoder := gob.NewDecoder(conn)
	if err := decoder.Decode(&frame); err != nil {
		return nil, err
	}
	return &RouterListener{
		routerAddress:  RouterAddress,
		decoder:        decoder,
		channel:        Channel,
		controlConn:    conn,
		connInitialier: ConnInitialier,
	}, nil
}

// NewRouterListener creates a RouterListener structure and try to handshake with Router in `RouterAddress`.
func NewRouterListener(RouterAddress string, Channel string) (*RouterListener, error) {
	return NewRouterListenerWithConn(RouterAddress, Channel, net.Dial)
}

// Close closes the listener.
func (listener *RouterListener) Close() error {
	gob.NewEncoder(listener.controlConn).Encode(RouterFrame{Type: Close})
	return listener.controlConn.Close()
}

// Addr returns the listener's address.
func (listener *RouterListener) Addr() net.Addr {
	return &RouterAddress{
		Channel: listener.channel,
	}
}

// Accept returns a bridged connection from a dial request.
func (listener *RouterListener) Accept() (net.Conn, error) {
	frame := RouterFrame{}
	for {
		if err := listener.decoder.Decode(&frame); err != nil {
			if err == io.EOF {
				return nil, nil
			}
			log.Print(err.Error())
			continue
		}
		if frame.Type != Nop {
			break
		}
		frame = RouterFrame{}
	}
	if frame.Type != Bridge {
		return nil, fmt.Errorf("server returns invalid request type: %d, expect bridge: %v", frame.Type, frame)
	}
	conn, err := listener.connInitialier("tcp", listener.routerAddress)
	if err != nil {
		return nil, fmt.Errorf("cannot fork connection request: %v", err)
	}
	if err := gob.NewEncoder(conn).Encode(RouterFrame{
		Type:         Bridge,
		ConnectionID: frame.ConnectionID,
	}); err != nil {
		return nil, fmt.Errorf("failed to handshake: %v", err)
	}
	return conn, nil
}
