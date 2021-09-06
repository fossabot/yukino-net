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

// receiverConnection is a structure to store the regitered channel.
type receiverConnection struct {
	routerConnection
	inflightConnection chan *routerConnection

	backfillSig sync.Mutex
	cond        *sync.Cond
}

// isClosed returns if the connection is closed.
func (conn *routerConnection) isClosed() bool {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	return conn.isclosed
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

// waitBackFillSignal blocks until `signalBackfill` is called.
func (conn *receiverConnection) waitBackFillSignal() {
	conn.backfillSig.Lock()
	conn.cond.Wait()
	conn.backfillSig.Unlock()
}

// signalBackfill will wake up all thread blocked by `waitBackFillSignal`.
func (conn *receiverConnection) signalBackfill() {
	conn.backfillSig.Lock()
	conn.cond.Broadcast()
	conn.backfillSig.Unlock()
}

func (conn *receiverConnection) close() {
	conn.backfillSig.Lock()
	if !conn.routerConnection.isClosed() {
		conn.routerConnection.close()
		close(conn.inflightConnection)
	}
	conn.cond.Broadcast()
	conn.backfillSig.Unlock()
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
	return conn.writeFrame(&RouterFrame{Type: Nop}) == nil
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

// SpawnBackfillInvoker will detach a goroutine to backfill connections from routerlistener.
// Exit when the ReceiverConnection is closed.
func (conn *receiverConnection) SpawnBackfillInvoker() {
	go func(receiverChannel chan *routerConnection) {
		for !conn.isClosed() {
			if len(receiverChannel) < InflightPoolMaxSize {
				if err := conn.writeFrame(&RouterFrame{
					Type: Bridge,
				}); err != nil {
					continue
				}
			}
			conn.waitBackFillSignal()
		}
	}(conn.inflightConnection)
}
