package router

import (
	"crypto/tls"
	"fmt"
	"io"
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
	tlsConfig     *tls.Config
	acceptorChan  chan net.Conn
	closedSig     chan struct{}

	mu              sync.Mutex
	isClosed        bool
	activeAcceptors int
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
		acceptorChan:  make(chan net.Conn),
		closedSig:     make(chan struct{}),

		mu:              sync.Mutex{},
		isClosed:        false,
		activeAcceptors: 0,
	}
	controlConn, err := routerListener.createConnection("tcp", RouterAddress)
	if err != nil {
		return nil, err
	}
	if tlsConn, ok := controlConn.(*tls.Conn); ok {
		log.Printf("Connection is built above TLS")
		log.Printf("CipherSuite: %s", tls.CipherSuiteName(tlsConn.ConnectionState().CipherSuite))
	}
	if err := writeFrame(&Frame{
		Type:    proto.Listen,
		Channel: Channel,
	}, controlConn); err != nil {
		controlConn.Close()
		return nil, err
	}
	if err := readFrame(&Frame{}, controlConn); err != nil {
		controlConn.Close()
		return nil, err
	}
	go routerListener.spawnController(controlConn)
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
	close(listener.acceptorChan)
	close(listener.closedSig)
	return nil
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

func (listener *Listener) incAcceptorCount(cnt int) {
	listener.mu.Lock()
	listener.activeAcceptors += cnt
	listener.mu.Unlock()
}

func (listener *Listener) acceptorCount() int {
	listener.mu.Lock()
	defer listener.mu.Unlock()
	return listener.activeAcceptors
}

func (listener *Listener) spawnController(controlConn net.Conn) {
	defer listener.Close()
	go func() {
		<-listener.closedSig
		controlConn.Close()
	}()
	frame := Frame{}
	for !listener.IsClosed() {
		if err := readFrame(&frame, controlConn); err != nil {
			listener.Close()
			return
		}
		if frame.Type == proto.Nop {
			if err := writeFrame(&nopFrame, controlConn); err != nil {
				listener.Close()
				return
			}
		}
		if frame.Type == proto.Bridge && listener.acceptorCount() > 0 {
			go func(connectionID uint64) {
				conn, err := listener.createConnection("tcp", listener.routerAddress)
				if err != nil {
					log.Printf("cannot fork connection request: %v", err)
					listener.Close()
				}
				if err := writeFrame(&Frame{
					Type:         proto.Bridge,
					Channel:      listener.channel,
					ConnectionID: connectionID,
				}, conn); err != nil {
					log.Printf("failed to handshake: %v", err)
					conn.Close()
					return
				}
				frame := Frame{}
				if err := readFrame(&frame, conn); err != nil {
					log.Printf("failed while finishing handshake: %v", err)
					conn.Close()
					return
				}
				listener.acceptorChan <- conn
			}(frame.ConnectionID)
		}
	}
}

// Accept returns a bridged connection from a dial request.
func (listener *Listener) Accept() (net.Conn, error) {
	listener.incAcceptorCount(1)
	defer listener.incAcceptorCount(-1)

	conn, ok := <-listener.acceptorChan
	if ok {
		return conn, nil
	}
	return nil, io.EOF
}
