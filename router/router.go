package router

import (
	"bufio"
	"context"
	"encoding/gob"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"
)

const (
	Dial   = byte(iota)
	Listen = byte(iota)
	Bridge = byte(iota)
	Nop    = byte(iota)
	Close  = byte(iota)

	DialConnectionTimeout     = 2 * time.Second
	ListenConnectionKeepAlive = 10 * time.Second
)

// RouterFrame is the packet using between Router.
type RouterFrame struct {
	Type         byte
	Channel      string
	ConnectionID uint64
}

// RouterConnection is a net.Conn wrapper.
type RouterConnection struct {
	mu         sync.Mutex
	Connection net.Conn
	Encoder    *gob.Encoder

	isClosed bool
	// Closed is a signal indicates this connection is ready to be GCed.
	Closed chan struct{}
}

// Close marks a connection as closed state.
func (conn *RouterConnection) Close() {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	if conn.isClosed {
		return
	}
	conn.Connection.Close()
	close(conn.Closed)
	conn.isClosed = true
}

func (conn *RouterConnection) writeFrame(frame *RouterFrame) error {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	if err := conn.Encoder.Encode(*frame); err != nil {
		return err
	}
	return nil
}

func NewConn(conn net.Conn) *RouterConnection {
	return &RouterConnection{
		mu:         sync.Mutex{},
		Connection: conn,
		Encoder:    gob.NewEncoder(conn),
		isClosed:   false,
		Closed:     make(chan struct{}),
	}
}

// probe returns whether the connection is healthy.
func (conn *RouterConnection) probe() bool {
	return conn.writeFrame(&RouterFrame{Type: Nop, Channel: "", ConnectionID: 0}) == nil
}

// Router proxies requests.
type Router struct {
	mu               sync.RWMutex
	inflightTable    map[uint64]*RouterConnection // temporary stores inflight dial request
	receiverTable    map[string]*RouterConnection // control channel to the receiver.
	nextConnectionID uint64
}

// NewRouter creates a Router structure.
func NewRouter() *Router {
	return &Router{
		mu:               sync.RWMutex{},
		inflightTable:    make(map[uint64]*RouterConnection),
		receiverTable:    make(map[string]*RouterConnection),
		nextConnectionID: 0,
	}
}

// SpawnConnectionChecker pings the connection periodically, returns and close the channel if any error encountered.
func (conn *RouterConnection) SpawnConnectionChecker(duration time.Duration) {
	go func() {
		ticker := time.NewTicker(duration)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if !conn.probe() {
					conn.Close()
					return
				}
			case <-conn.Closed:
				conn.Close()
				return
			}
		}
	}()
}

// handleListen handles a listen type of connection.
// It is caller's responsibility to close the connection.
func (router *Router) handleListen(channel string, conn net.Conn) error {
	controlConnection := NewConn(conn)
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

	if !controlConnection.probe() {
		return nil
	}

	controlConnection.SpawnConnectionChecker(ListenConnectionKeepAlive)

	frame := RouterFrame{}
	if err := gob.NewDecoder(controlConnection.Connection).Decode(&frame); err != nil {
		return err
	}
	if frame.Type == Close {
		controlConnection.Close()
		return nil
	}

	<-controlConnection.Closed
	return nil
}

// handleDial handles a dial request.
func (router *Router) handleDial(frame *RouterFrame, conn net.Conn) error {
	dialConnection := NewConn(conn)
	if dialConn, ok := conn.(*net.TCPConn); ok {
		dialConn.SetKeepAlive(true)
		dialConn.SetKeepAlivePeriod(ListenConnectionKeepAlive)
	}
	conn.SetDeadline(time.Now().Add(DialConnectionTimeout))
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
		Type:         Bridge,
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

	router.mu.Lock()
	peerConn, exist := router.inflightTable[frame.ConnectionID]
	delete(router.inflightTable, frame.ConnectionID)
	router.mu.Unlock()
	peerConn.Connection.SetDeadline(time.Time{})

	if !exist {
		return fmt.Errorf("handshake failed, might be failed due to timeout")
	}

	if err := peerConn.writeFrame(&RouterFrame{
		Type:         Bridge,
		Channel:      "",
		ConnectionID: 0,
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

	peerConn.Close()
	return nil
}

// handleConnection takes the responsibility to close the connection once done.
func (router *Router) handleConnection(conn net.Conn) error {
	defer conn.Close()
	decoder := gob.NewDecoder(conn)
	frame := RouterFrame{}

	if err := decoder.Decode(&frame); err != nil {
		return fmt.Errorf("closing connection from %v due to error: %v", conn.RemoteAddr(), err)
	}

	switch frame.Type {
	case Listen:
		return router.handleListen(frame.Channel, conn)
	case Bridge:
		return router.handleBridge(&frame, conn)
	case Dial:
		return router.handleDial(&frame, conn)
	}
	return nil
}

// Serve starts the serving process, this is a blocking call.
func (router *Router) Serve(listener net.Listener) error {
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("router serve returns err: %v", err)
			return err
		}
		go router.handleConnection(conn)
	}
}
