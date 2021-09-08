package router

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/xpy123993/router/router/proto"
)

const (
	// InflightPoolMaxSize specifies the maximum pre-allocate connections for each receiver.
	DefaultInflightPoolMaxSize       = 0
	DefaultDialConnectionTimeout     = 2 * time.Second
	DefaultListenConnectionKeepAlive = 20 * time.Second
)

// Authority will b e used by the router for ACL control.
type Authority interface {
	// Returns if the permission check is passed for `frame`.
	CheckPermission(frame *RouterFrame) bool

	// Returns the expiration time of the key. Router will use this to set a connection deadline.
	GetExpirationTime(key []byte) time.Time
}

type noPermissionCheckAuthority struct{}

func (*noPermissionCheckAuthority) CheckPermission(*RouterFrame) bool { return true }
func (*noPermissionCheckAuthority) GetExpirationTime([]byte) time.Time {
	return time.Now().Add(24 * time.Hour)
}

// RouterOption specifies a set of options being used by the router.
type RouterOption struct {
	// TokenAuthority is the authority used for checking permissions.
	TokenAuthority Authority
	// DialConnectionTimeout specifies the timeout when a dialer connects to a listener.
	DialConnectionTimeout time.Duration
	// ListenConnectionKeepAlive specfies the health check interval.
	ListenConnectionKeepAlive time.Duration
	// TLSConfig specifies the TLS setting, if empty, the traffic will not be encrypted.
	TLSConfig *tls.Config
}

var DefaultRouterOption = RouterOption{
	TokenAuthority:            &noPermissionCheckAuthority{},
	DialConnectionTimeout:     DefaultDialConnectionTimeout,
	ListenConnectionKeepAlive: DefaultListenConnectionKeepAlive,
}

// Router proxies requests.
type Router struct {
	option           RouterOption
	mu               sync.RWMutex
	receiverTable    map[string]*routerConnection // control channel to the receiver.
	inflightTable    map[uint64]*routerConnection
	nextConnectionID uint64
}

// NewRouter creates a Router structure.
func NewRouter(option RouterOption) *Router {
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
	if _, exists := router.receiverTable[channel]; exists {
		router.mu.Unlock()
		return fmt.Errorf("channel %s is already registered", channel)
	}
	router.receiverTable[channel] = controlConnection
	router.mu.Unlock()

	defer func() {
		router.mu.Lock()
		delete(router.receiverTable, channel)
		router.mu.Unlock()
	}()

	controlConnection.SpawnConnectionChecker(router.option.ListenConnectionKeepAlive)

	if !controlConnection.probe() {
		return nil
	}

	frame := RouterFrame{}
	if err := readFrame(&frame, controlConnection.Connection); err != nil {
		return err
	}
	if frame.Type == proto.Close {
		controlConnection.close()
		return nil
	}

	<-controlConnection.Closed
	return nil
}

// handleDial handles a dial request.
func (router *Router) handleDial(frame *RouterFrame, conn net.Conn) error {
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
	if err := controlConnection.writeFrame(&RouterFrame{
		Type:         proto.Bridge,
		Channel:      "",
		ConnectionID: connectionID,
	}); err != nil {
		return err
	}

	<-dialConnection.Closed
	return nil

}

func (router *Router) handleBridge(frame *RouterFrame, conn net.Conn) error {
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

	if err := peerConn.writeFrame(&RouterFrame{
		Type: proto.Bridge,
	}); err != nil {
		return err
	}
	if err := connection.writeFrame(&RouterFrame{
		Type: proto.Bridge,
	}); err != nil {
		return err
	}

	go func() {
		io.Copy(peerConn.Connection, bufio.NewReader(conn))
		cancelFn()
	}()

	go func() {
		io.Copy(conn, bufio.NewReader(peerConn.Connection))
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
	frame := RouterFrame{}

	if err := readFrame(&frame, conn); err != nil {
		return fmt.Errorf("closing connection from %v due to error: %v", conn.RemoteAddr(), err)
	}
	if !router.option.TokenAuthority.CheckPermission(&frame) {
		return fmt.Errorf("permission denied: invalid token `%s`",
			base64.RawStdEncoding.EncodeToString(frame.Token))
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
			if err := router.handleConnection(conn); err != nil {
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
