package common

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"encoding/gob"
	"fmt"
	"io"
)

// WriteWithZlib dumps data into conn, returns any error encountered.
func WriteWithZlib(conn io.Writer, data interface{}) error {
	buf := bytes.Buffer{}
	writer := zlib.NewWriter(&buf)
	if err := gob.NewEncoder(writer).Encode(data); err != nil {
		return err
	}
	writer.Close()
	bufSize := int32(buf.Len())
	if err := binary.Write(conn, binary.BigEndian, &bufSize); err != nil {
		return err
	}
	if n, err := conn.Write(buf.Bytes()); err != nil {
		return err
	} else if n != buf.Len() {
		return fmt.Errorf("work not done: (actual) %d vs %d", n, buf.Len())
	}
	return nil
}

// ReadWithZlib reads data from conn, returns any error encountered.
func ReadWithZlib(conn io.Reader, data interface{}) error {
	var bufSize int32
	if err := binary.Read(conn, binary.BigEndian, &bufSize); err != nil {
		if err == io.EOF {
			return err
		}
		return fmt.Errorf("cannot determine next packet size: %s", err.Error())
	}
	if bufSize > 8192 {
		return fmt.Errorf("packet size too large: %d > limit 8192", bufSize)
	}
	buf := make([]byte, bufSize)
	if n, err := io.ReadFull(conn, buf); err != nil {
		return err
	} else if n != int(bufSize) {
		return fmt.Errorf("not fully returned")
	}
	reader, err := zlib.NewReader(bytes.NewReader(buf))
	if err != nil {
		return err
	}
	err = gob.NewDecoder(reader).Decode(data)
	if err != nil {
		return fmt.Errorf("error while decoding data: %s", err.Error())
	}
	return nil
}
