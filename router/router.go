package router

import (
	"context"
	"crypto/tls"
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
	DefaultInflightPoolMaxSize       = 16
	DefaultDialConnectionTimeout     = 2 * time.Second
	DefaultListenConnectionKeepAlive = 20 * time.Second
)

// Authority will b e used by the router for ACL control.
type Authority interface {
	// Returns if the permission check is passed for `frame`.
	CheckPermission(frame *RouterFrame) bool
}

type noPermissionCheckAuthority struct{}

func (*noPermissionCheckAuthority) CheckPermission(*RouterFrame) bool { return true }

// RouterOption specifies a set of options being used by the router.
type RouterOption struct {
	// TokenAuthority is the authority used for checking permissions.
	TokenAuthority Authority
	// InflightPoolMaxSize specifies how many free connections can be pre-allocated to serve future requests.
	InflightPoolMaxSize int
	// DialConnectionTimeout specifies the timeout when a dialer connects to a listener.
	DialConnectionTimeout time.Duration
	// ListenConnectionKeepAlive specfies the health check interval.
	ListenConnectionKeepAlive time.Duration
	// TLSConfig specifies the TLS setting, if empty, the traffic will not be encrypted.
	TLSConfig *tls.Config
}

var DefaultRouterOption = RouterOption{
	TokenAuthority:            &noPermissionCheckAuthority{},
	InflightPoolMaxSize:       DefaultInflightPoolMaxSize,
	DialConnectionTimeout:     DefaultDialConnectionTimeout,
	ListenConnectionKeepAlive: DefaultListenConnectionKeepAlive,
}

// Router proxies requests.
type Router struct {
	option        RouterOption
	mu            sync.RWMutex
	receiverTable map[string]*receiverConnection // control channel to the receiver.
}

// NewRouter creates a Router structure.
func NewRouter(option RouterOption) *Router {
	return &Router{
		mu:            sync.RWMutex{},
		receiverTable: make(map[string]*receiverConnection),
		option:        option,
	}
}

// NewDefaultRouter creates a router with default option.
func NewDefaultRouter() *Router {
	return &Router{
		mu:            sync.RWMutex{},
		receiverTable: make(map[string]*receiverConnection),
		option:        DefaultRouterOption,
	}
}

// handleListen handles a listen type of connection.
// It is caller's responsibility to close the connection.
func (router *Router) handleListen(channel string, conn net.Conn) error {
	controlConnection := receiverConnection{
		routerConnection:   *newConn(conn),
		inflightConnection: make(chan *routerConnection, router.option.InflightPoolMaxSize),
		backfillSig:        sync.Mutex{},
	}
	controlConnection.cond = sync.NewCond(&controlConnection.backfillSig)

	router.mu.Lock()
	if _, exists := router.receiverTable[channel]; exists {
		router.mu.Unlock()
		return fmt.Errorf("channel %s is already registered", channel)
	}
	router.receiverTable[channel] = &controlConnection
	router.mu.Unlock()

	defer func() {
		router.mu.Lock()
		delete(router.receiverTable, channel)
		router.mu.Unlock()
	}()

	controlConnection.SpawnConnectionChecker(router.option.ListenConnectionKeepAlive)
	controlConnection.SpawnBackfillInvoker(router.option.InflightPoolMaxSize)

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
	defer dialConnection.close()
	if dialConn, ok := conn.(*net.TCPConn); ok {
		dialConn.SetKeepAlive(true)
		dialConn.SetKeepAlivePeriod(router.option.DialConnectionTimeout)
	}
	conn.SetDeadline(time.Now().Add(router.option.DialConnectionTimeout))
	router.mu.Lock()

	receiverChan, exist := router.receiverTable[frame.Channel]
	if !exist {
		router.mu.Unlock()
		return fmt.Errorf("channel %s is not registered", frame.Channel)
	}

	router.mu.Unlock()

	receiverChan.signalBackfill()
	var peerConn *routerConnection
	var ok bool

	select {
	case peerConn, ok = <-receiverChan.inflightConnection:
		if !ok {
			return nil
		}
	case <-dialConnection.Closed:
		return nil
	case <-receiverChan.Closed:
		return nil
	}
	defer peerConn.close()

	conn.SetDeadline(time.Time{})
	receiverChan.signalBackfill()

	if err := writeFrame(&RouterFrame{
		Type:    proto.Bridge,
		Token:   "",
		Channel: "",
	}, conn); err != nil {
		return err
	}
	peerConn.writeFrame(&RouterFrame{
		Type:    proto.Bridge,
		Token:   "",
		Channel: "",
	})

	ctx, cancelFn := context.WithCancel(context.Background())
	defer cancelFn()

	go func() {
		io.Copy(peerConn.Connection, conn)
		cancelFn()
	}()

	go func() {
		io.Copy(conn, peerConn.Connection)
		cancelFn()
	}()

	<-ctx.Done()
	return nil
}

func (router *Router) handleBridge(frame *RouterFrame, conn net.Conn) error {
	connection := newConn(conn)
	defer connection.close()
	router.mu.Lock()
	receiverChannel, exist := router.receiverTable[frame.Channel]
	router.mu.Unlock()
	if !exist {
		return fmt.Errorf("handshake failed, might be failed due to timeout")
	}

	select {
	case <-time.After(router.option.DialConnectionTimeout):
		connection.close()
		return nil
	case <-receiverChannel.Closed:
		return nil
	case receiverChannel.inflightConnection <- connection:
	}

	receiverChannel.signalBackfill()
	<-connection.Closed
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
		return fmt.Errorf("permission denied: frame: %v", frame)
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
