package router

import (
	"fmt"
	"net"
	"sync"
	"time"
)

// routerConnection is a net.Conn wrapper.
type routerConnection struct {
	mu         sync.Mutex
	Connection net.Conn

	isclosed bool
	// Closed is a signal indicates this connection is ready to be GCed.
	Closed chan struct{}
}

// close marks a connection as closed state.
func (conn *routerConnection) close() {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	if conn.isclosed {
		return
	}
	conn.Connection.Close()
	close(conn.Closed)
	conn.isclosed = true
}

func (conn *routerConnection) writeFrame(frame *Frame) error {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	if conn.isclosed {
		return fmt.Errorf("connection is already closed")
	}
	return writeFrame(frame, conn.Connection)
}

func newConn(conn net.Conn) *routerConnection {
	return &routerConnection{
		mu:         sync.Mutex{},
		Connection: conn,
		isclosed:   false,
		Closed:     make(chan struct{}),
	}
}

// probe returns whether the connection is healthy.
func (conn *routerConnection) probe() bool {
	conn.Connection.SetDeadline(time.Now().Add(DefaultDialConnectionTimeout))
	defer conn.Connection.SetDeadline(time.Time{})
	if err := conn.writeFrame(&nopFrame); err != nil {
		return false
	}
	return readFrame(&Frame{}, conn.Connection) == nil
}

// SpawnConnectionChecker pings the connection periodically, returns and close the channel if any error encountered.
func (conn *routerConnection) SpawnConnectionChecker(duration time.Duration) {
	go func() {
		ticker := time.NewTicker(duration)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if !conn.probe() {
					conn.close()
					return
				}
			case <-conn.Closed:
				conn.close()
				return
			}
		}
	}()
}
