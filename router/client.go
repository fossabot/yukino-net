package router

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"

	"github.com/xpy123993/router/router/proto"
)

// RouterClient implements a Dial method to join the Router network.
type RouterClient struct {
	// The public address of the Router.
	routerAddress string
	// token used for permission validation.
	token string
	// If not nil, the client will use tls.Dial to connect to the Router.
	tlsConfig *tls.Config
}

// NewClientWithoutAuth creates a RouterClient structure.
func NewClientWithoutAuth(RouterAddress string) *RouterClient {
	return &RouterClient{
		routerAddress: RouterAddress,
	}
}

// NewClient creates a RouterClient with permision settings.
func NewClient(RouterAddress string, Token string, TLSConfig *tls.Config) *RouterClient {
	return &RouterClient{
		routerAddress: RouterAddress,
		token:         Token,
		tlsConfig:     TLSConfig,
	}
}

// Dial initiaites a dial request into the Route network.
func (client *RouterClient) Dial(TargetChannel string) (net.Conn, error) {
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
	if err := writeFrame(&RouterFrame{
		Type:    proto.Dial,
		Token:   client.token,
		Channel: TargetChannel,
	}, conn); err != nil {
		return nil, err
	}
	frame := RouterFrame{}
	if err := readFrame(&frame, conn); err != nil {
		return nil, err
	}
	return conn, nil
}

// RouterListener implements a net.Listener interface on Router network.
type RouterListener struct {
	routerAddress string
	channel       string
	token         string
	controlConn   net.Conn
	tlsConfig     *tls.Config
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
	RouterAddress string, Token string, Channel string, TLSConfig *tls.Config) (*RouterListener, error) {
	routerListener := RouterListener{
		routerAddress: RouterAddress,
		channel:       Channel,
		token:         Token,
		tlsConfig:     TLSConfig,
	}
	var err error
	routerListener.controlConn, err = routerListener.createConnection("tcp", RouterAddress)
	if err != nil {
		return nil, err
	}
	if tlsConn, ok := routerListener.controlConn.(*tls.Conn); ok {
		log.Printf("connection is built above TLS")
		log.Printf("CipherSuite: %s", tls.CipherSuiteName(tlsConn.ConnectionState().CipherSuite))
	}
	if err := writeFrame(&RouterFrame{
		Type:    proto.Listen,
		Token:   Token,
		Channel: Channel,
	}, routerListener.controlConn); err != nil {
		return nil, err
	}
	frame := RouterFrame{}
	if err := readFrame(&frame, routerListener.controlConn); err != nil {
		return nil, err
	}
	return &routerListener, nil
}

func (listener *RouterListener) createConnection(network, address string) (net.Conn, error) {
	if listener.tlsConfig != nil {
		return tls.Dial(network, address, listener.tlsConfig)
	}
	return net.Dial(network, address)
}

// NewListenerWithoutAuth creates a RouterListener structure and try to handshake with Router in `RouterAddress`.
func NewListenerWithoutAuth(RouterAddress string, Channel string) (*RouterListener, error) {
	return NewRouterListenerWithConn(RouterAddress, "", Channel, nil)
}

// NewListener creates a RouterListener.
func NewListener(RouterAddress, Token, Channel string, TLSConfig *tls.Config) (*RouterListener, error) {
	return NewRouterListenerWithConn(RouterAddress, Token, Channel, TLSConfig)
}

// Close closes the listener.
func (listener *RouterListener) Close() error {
	writeFrame(&RouterFrame{Type: proto.Close}, listener.controlConn)
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
		if err := readFrame(&frame, listener.controlConn); err != nil {
			if err == io.EOF {
				return nil, err
			}
			continue
		}
		if frame.Type != proto.Nop {
			break
		}
	}
	if frame.Type != proto.Bridge {
		return nil, fmt.Errorf("server returns invalid request type: %d, expect bridge: %v", frame.Type, frame)
	}
	conn, err := listener.createConnection("tcp", listener.routerAddress)
	if err != nil {
		return nil, fmt.Errorf("cannot fork connection request: %v", err)
	}
	if err := writeFrame(&RouterFrame{
		Type:    proto.Bridge,
		Token:   listener.token,
		Channel: listener.channel,
	}, conn); err != nil {
		return nil, fmt.Errorf("failed to handshake: %v", err)
	}
	if err := readFrame(&frame, conn); err != nil {
		return listener.Accept()
	}
	return conn, nil
}
