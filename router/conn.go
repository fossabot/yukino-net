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

func (conn *routerConnection) writeFrame(frame *RouterFrame) error {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	if conn.isclosed {
		return fmt.Errorf("connection is already closed")
	}
	if err := writeFrame(frame, conn.Connection); err != nil {
		return err
	}
	return nil
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
	return conn.writeFrame(&nopFrame) == nil
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
