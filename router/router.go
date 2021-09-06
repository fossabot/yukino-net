package router

import (
	"context"
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

	// InflightPoolMaxSize specifies the maximum pre-allocate connections for each receiver.
	InflightPoolMaxSize       = 16
	DialConnectionTimeout     = 2 * time.Second
	ListenConnectionKeepAlive = 20 * time.Second
)

// RouterFrame is the packet using between Router.
type RouterFrame struct {
	Type    byte
	Channel string
}

// Router proxies requests.
type Router struct {
	mu            sync.RWMutex
	receiverTable map[string]*receiverConnection // control channel to the receiver.
}

// NewRouter creates a Router structure.
func NewRouter() *Router {
	return &Router{
		mu:            sync.RWMutex{},
		receiverTable: make(map[string]*receiverConnection),
	}
}

// handleListen handles a listen type of connection.
// It is caller's responsibility to close the connection.
func (router *Router) handleListen(channel string, conn net.Conn) error {
	controlConnection := receiverConnection{
		routerConnection:   *newConn(conn),
		inflightConnection: make(chan *routerConnection, InflightPoolMaxSize),
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

	controlConnection.SpawnConnectionChecker(ListenConnectionKeepAlive)
	controlConnection.SpawnBackfillInvoker()

	if !controlConnection.probe() {
		return nil
	}

	frame := RouterFrame{}
	if err := readFrame(&frame, controlConnection.Connection); err != nil {
		return err
	}
	if frame.Type == Close {
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
		dialConn.SetKeepAlivePeriod(DialConnectionTimeout)
	}
	conn.SetDeadline(time.Now().Add(DialConnectionTimeout))
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
		Type: Bridge,
	}, conn); err != nil {
		return err
	}
	peerConn.writeFrame(&RouterFrame{
		Type: Bridge,
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
	case <-time.After(DialConnectionTimeout):
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
			return err
		}
		go func() {
			if err := router.handleConnection(conn); err != nil {
				log.Print(err.Error())
			}
		}()
	}
}
