package router

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"sync"

	"github.com/xpy123993/yukino-net/libraries/router/proto"
)

// Client implements a Dial method to join the Router network.
type Client struct {
	// The public address of the Router.
	routerAddress string
	// If not nil, the client will use tls.Dial to connect to the Router.
	tlsConfig *tls.Config
}

// NewClientWithoutAuth creates a RouterClient structure.
func NewClientWithoutAuth(RouterAddress string) *Client {
	return &Client{
		routerAddress: RouterAddress,
	}
}

// NewClient creates a RouterClient with permision settings.
func NewClient(RouterAddress string, TLSConfig *tls.Config) *Client {
	return &Client{
		routerAddress: RouterAddress,
		tlsConfig:     TLSConfig,
	}
}

// Dial initiaites a dial request into the Route network.
func (client *Client) Dial(TargetChannel string) (net.Conn, error) {
	var conn net.Conn
	var err error

	if client.tlsConfig != nil {
		conn, err = tls.Dial("tcp", client.routerAddress, client.tlsConfig)
	} else {
		conn, err = net.Dial("tcp", client.routerAddress)
	}
	if err != nil {
		return nil, err
	}
	if err := writeFrame(&Frame{
		Type:    proto.Dial,
		Channel: TargetChannel,
	}, conn); err != nil {
		return nil, err
	}
	frame := Frame{}
	if err := readFrame(&frame, conn); err != nil {
		return nil, err
	}
	if frame.Type != proto.Bridge {
		return nil, fmt.Errorf("invalid response")
	}
	return conn, nil
}

// Listener implements a net.Listener interface on Router network.
type Listener struct {
	routerAddress string
	channel       string
	controlConn   net.Conn
	tlsConfig     *tls.Config

	mu       sync.Mutex
	isClosed bool
}

// Address represents an address in Router network.
type Address struct {
	Channel string
}

// Network returns the network type.
func (*Address) Network() string {
	return "Yukino"
}

// String return the channel name of this address.
func (address *Address) String() string {
	return address.Channel
}

// NewRouterListenerWithConn creates a RouterListener structure.
// Conn here can be a just initialized connectiono from TLS.
func NewRouterListenerWithConn(
	RouterAddress string, Channel string, TLSConfig *tls.Config) (*Listener, error) {
	routerListener := Listener{
		routerAddress: RouterAddress,
		channel:       Channel,
		tlsConfig:     TLSConfig,

		mu:       sync.Mutex{},
		isClosed: false,
	}
	var err error
	routerListener.controlConn, err = routerListener.createConnection("tcp", RouterAddress)
	if err != nil {
		return nil, err
	}
	if tlsConn, ok := routerListener.controlConn.(*tls.Conn); ok {
		log.Printf("Connection is built above TLS")
		log.Printf("CipherSuite: %s", tls.CipherSuiteName(tlsConn.ConnectionState().CipherSuite))
	}
	if err := writeFrame(&Frame{
		Type:    proto.Listen,
		Channel: Channel,
	}, routerListener.controlConn); err != nil {
		return nil, err
	}
	if err := readFrame(&Frame{}, routerListener.controlConn); err != nil {
		return nil, err
	}
	return &routerListener, nil
}

func (listener *Listener) createConnection(network, address string) (net.Conn, error) {
	if listener.tlsConfig != nil {
		return tls.Dial(network, address, listener.tlsConfig)
	}
	return net.Dial(network, address)
}

// NewListenerWithoutAuth creates a RouterListener structure and try to handshake with Router in `RouterAddress`.
func NewListenerWithoutAuth(RouterAddress string, Channel string) (*Listener, error) {
	return NewRouterListenerWithConn(RouterAddress, Channel, nil)
}

// NewListener creates a RouterListener.
func NewListener(RouterAddress string, Channel string, TLSConfig *tls.Config) (*Listener, error) {
	return NewRouterListenerWithConn(RouterAddress, Channel, TLSConfig)
}

// Close closes the listener.
func (listener *Listener) Close() error {
	listener.mu.Lock()
	defer listener.mu.Unlock()
	if listener.isClosed {
		return nil
	}
	listener.isClosed = true
	writeFrame(&Frame{Type: proto.Close}, listener.controlConn)
	return listener.controlConn.Close()
}

// Addr returns the listener's address.
func (listener *Listener) Addr() net.Addr {
	return &Address{
		Channel: listener.channel,
	}
}

// IsClosed returns whether the listener is closed.
func (listener *Listener) IsClosed() bool {
	listener.mu.Lock()
	defer listener.mu.Unlock()
	return listener.isClosed
}

// Accept returns a bridged connection from a dial request.
func (listener *Listener) Accept() (net.Conn, error) {
	frame := Frame{}
	for listener != nil {
		if err := readFrame(&frame, listener.controlConn); err != nil {
			return nil, err
		}
		if frame.Type != proto.Nop {
			break
		}
		if err := writeFrame(&nopFrame, listener.controlConn); err != nil {
			return nil, err
		}
	}
	if frame.Type != proto.Bridge {
		return nil, fmt.Errorf("server returns invalid request type: %d, expect bridge: %v", frame.Type, frame)
	}
	conn, err := listener.createConnection("tcp", listener.routerAddress)
	if err != nil {
		return nil, fmt.Errorf("cannot fork connection request: %v", err)
	}
	if err := writeFrame(&Frame{
		Type:         proto.Bridge,
		Channel:      listener.channel,
		ConnectionID: frame.ConnectionID,
	}, conn); err != nil {
		return nil, fmt.Errorf("failed to handshake: %v", err)
	}
	if err := readFrame(&frame, conn); err != nil {
		return nil, fmt.Errorf("failed while finishing handshake: %v", err)
	}
	return conn, nil
}
