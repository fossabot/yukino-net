package router

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/xpy123993/yukino-net/libraries/router/keystore"
	"github.com/xpy123993/yukino-net/libraries/router/proto"
)

const (
	// DefaultDialConnectionTimeout is the default timeout for a dial operation.
	DefaultDialConnectionTimeout = 2 * time.Second
	// DefaultListenConnectionKeepAlive is the default keep alive checking interval for listening threads.
	DefaultListenConnectionKeepAlive = 20 * time.Second
	// DefaultServerBufferBytes is the default buffer size to exchange between connections.
	DefaultServerBufferBytes = 4096
)

// Authority will b e used by the router for ACL control.
type Authority interface {
	// Returns if the permission check is passed for `frame`.
	CheckPermission(frame *Frame, key []byte) bool

	// Returns the expiration time of the key. Router will use this to set a connection deadline.
	GetExpirationTime(key []byte) time.Time
}

type noPermissionCheckAuthority struct{}

func (*noPermissionCheckAuthority) CheckPermission(*Frame, []byte) bool { return true }
func (*noPermissionCheckAuthority) GetExpirationTime([]byte) time.Time {
	return time.Now().Add(24 * time.Hour)
}

// Option specifies a set of options being used by the router.
type Option struct {
	// TokenAuthority is the authority used for checking permissions.
	TokenAuthority Authority
	// DialConnectionTimeout specifies the timeout when a dialer connects to a listener.
	DialConnectionTimeout time.Duration
	// ListenConnectionKeepAlive specfies the health check interval.
	ListenConnectionKeepAlive time.Duration
	// TLSConfig specifies the TLS setting, if empty, the traffic will not be encrypted.
	TLSConfig *tls.Config
	// ChannelBufferBytes specifies the size of the buffer while bridging the channel.
	ChannelBufferBytes uint64
}

// DefaultRouterOption is a set of parameters in default value.
var DefaultRouterOption = Option{
	TokenAuthority:            &noPermissionCheckAuthority{},
	DialConnectionTimeout:     DefaultDialConnectionTimeout,
	ListenConnectionKeepAlive: DefaultListenConnectionKeepAlive,
	ChannelBufferBytes:        DefaultServerBufferBytes,
}

// Router proxies requests.
type Router struct {
	option           Option
	mu               sync.RWMutex
	receiverTable    map[string]*routerConnection // control channel to the receiver.
	inflightTable    map[uint64]*routerConnection
	nextConnectionID uint64
}

// NewRouter creates a Router structure.
func NewRouter(option Option) *Router {
	return &Router{
		mu:            sync.RWMutex{},
		receiverTable: make(map[string]*routerConnection),
		inflightTable: make(map[uint64]*routerConnection),
		option:        option,
	}
}

// NewDefaultRouter creates a router with default option.
func NewDefaultRouter() *Router {
	return &Router{
		mu:            sync.RWMutex{},
		receiverTable: make(map[string]*routerConnection),
		option:        DefaultRouterOption,
		inflightTable: map[uint64]*routerConnection{},
	}
}

// handleListen handles a listen type of connection.
// It is caller's responsibility to close the connection.
func (router *Router) handleListen(channel string, conn net.Conn) error {
	controlConnection := newConn(conn)

	router.mu.Lock()
	if conn, exists := router.receiverTable[channel]; exists {
		if conn.probe() {
			// The listening thread is still active.
			router.mu.Unlock()
			return fmt.Errorf("channel %s is already registered", channel)
		}
		// Listening thread is dead, trigger the cleanup.
		conn.close()
	}
	router.receiverTable[channel] = controlConnection
	router.mu.Unlock()

	defer func() {
		router.mu.Lock()
		if controlConnection == router.receiverTable[channel] {
			delete(router.receiverTable, channel)
		}
		router.mu.Unlock()
	}()

	controlConnection.SpawnConnectionChecker(router.option.ListenConnectionKeepAlive)

	<-controlConnection.Closed
	return nil
}

// handleDial handles a dial request.
func (router *Router) handleDial(frame *Frame, conn net.Conn) error {
	dialConnection := newConn(conn)
	if dialConn, ok := conn.(*net.TCPConn); ok {
		dialConn.SetKeepAlive(true)
		dialConn.SetKeepAlivePeriod(router.option.DialConnectionTimeout)
	}
	conn.SetDeadline(time.Now().Add(router.option.DialConnectionTimeout))
	router.mu.Lock()

	controlConnection, exist := router.receiverTable[frame.Channel]
	if !exist {
		router.mu.Unlock()
		return fmt.Errorf("channel %s is not registered", frame.Channel)
	}
	connectionID := router.nextConnectionID
	router.nextConnectionID++
	router.inflightTable[connectionID] = dialConnection
	router.mu.Unlock()

	defer func() {
		router.mu.Lock()
		delete(router.inflightTable, connectionID)
		router.mu.Unlock()
	}()
	if err := controlConnection.writeFrame(&Frame{
		Type:         proto.Bridge,
		Channel:      "",
		ConnectionID: connectionID,
	}); err != nil {
		controlConnection.close()
		return err
	}

	<-dialConnection.Closed
	return nil
}

func (router *Router) handleBridge(frame *Frame, conn net.Conn) error {
	ctx, cancelFn := context.WithCancel(context.Background())
	defer cancelFn()

	connection := newConn(conn)

	router.mu.Lock()
	peerConn, exist := router.inflightTable[frame.ConnectionID]
	delete(router.inflightTable, frame.ConnectionID)
	router.mu.Unlock()
	if !exist {
		return fmt.Errorf("handshake failed, might be failed due to timeout")
	}
	peerConn.Connection.SetDeadline(time.Time{})

	if err := peerConn.writeFrame(&Frame{
		Type: proto.Bridge,
	}); err != nil {
		return err
	}
	if err := connection.writeFrame(&Frame{
		Type: proto.Bridge,
	}); err != nil {
		return err
	}

	go func() {
		io.Copy(peerConn.Connection, bufio.NewReaderSize(conn, int(router.option.ChannelBufferBytes)))
		cancelFn()
	}()

	go func() {
		io.Copy(conn, bufio.NewReaderSize(peerConn.Connection, int(router.option.ChannelBufferBytes)))
		cancelFn()
	}()

	<-ctx.Done()

	peerConn.close()
	connection.close()
	return nil
}

// handleConnection takes the responsibility to close the connection once done.
func (router *Router) handleConnection(conn net.Conn) error {
	defer conn.Close()
	frame := Frame{}

	if err := readFrame(&frame, conn); err != nil {
		return fmt.Errorf("closing connection from %v due to error: %v", conn.RemoteAddr(), err)
	}
	var key []byte
	if tlsConn, ok := conn.(*tls.Conn); ok {
		if err := tlsConn.Handshake(); err != nil {
			return fmt.Errorf("handshake failed with %s", conn.RemoteAddr().String())
		}
		key = tlsConn.ConnectionState().PeerCertificates[0].Signature
	}
	if !router.option.TokenAuthority.CheckPermission(&frame, key) {
		return fmt.Errorf("permission denied: peer token `%s` from address `%s`",
			keystore.HashKey(key), conn.RemoteAddr().String())
	}

	switch frame.Type {
	case proto.Listen:
		return router.handleListen(frame.Channel, conn)
	case proto.Bridge:
		return router.handleBridge(&frame, conn)
	case proto.Dial:
		return router.handleDial(&frame, conn)
	}
	return nil
}

// Serve starts the serving process, this is a blocking call.
func (router *Router) Serve(listener net.Listener) error {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		go func() {
			if err := router.handleConnection(conn); err != nil && err != io.EOF {
				log.Print(err.Error())
			}
		}()
	}
}

// ListenAndServe will try to listen on the specified address.
func (router *Router) ListenAndServe(Address string) error {
	var err error
	var listener net.Listener
	if router.option.TLSConfig != nil {
		listener, err = tls.Listen("tcp", Address, router.option.TLSConfig)
	} else {
		listener, err = net.Listen("tcp", Address)
	}
	if err != nil {
		return err
	}
	return router.Serve(listener)
}
