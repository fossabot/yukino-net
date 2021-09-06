package common

import "io"

type PeeredReadWriteCloser struct {
	Reader *io.PipeReader
	Writer *io.PipeWriter
}

type InMemoryConn struct {
	PeerA *PeeredReadWriteCloser
	PeerB *PeeredReadWriteCloser
}

func (c PeeredReadWriteCloser) Read(data []byte) (n int, err error)  { return c.Reader.Read(data) }
func (c PeeredReadWriteCloser) Write(data []byte) (n int, err error) { return c.Writer.Write(data) }
func (c PeeredReadWriteCloser) Close() (err error) {
	c.Reader.Close()
	c.Writer.Close()
	return nil
}

func (c InMemoryConn) Close() error {
	if err := c.PeerA.Close(); err != nil {
		return err
	}
	if err := c.PeerB.Close(); err != nil {
		return err
	}
	return nil
}

func NewPeerConn() InMemoryConn {
	serverRead, clientWrite := io.Pipe()
	clientRead, serverWrite := io.Pipe()

	return InMemoryConn{
		PeerA: &PeeredReadWriteCloser{
			Reader: serverRead,
			Writer: serverWrite,
		},
		PeerB: &PeeredReadWriteCloser{
			Reader: clientRead,
			Writer: clientWrite,
		},
	}
}
