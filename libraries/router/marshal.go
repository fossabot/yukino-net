package router

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/xpy123993/yukino-net/libraries/router/proto"
)

// MaxChannelNameLength limits the maxmimum length of a channel name.
const MaxChannelNameLength = 256

// Frame is the packet using between Router.
type Frame struct {
	Type         byte
	ConnectionID uint64
	Payload      string
}

var nopFrame = Frame{Type: proto.Nop}

func writeBytes(message []byte, writer io.Writer) error {
	if err := binary.Write(writer, binary.BigEndian, uint16(len(message))); err != nil {
		return err
	}
	if n, err := writer.Write(message); err != nil {
		return err
	} else if n != len(message) {
		return fmt.Errorf("string not fully write")
	}
	return nil
}

func readBytes(reader io.Reader) ([]byte, error) {
	var strLen uint16
	if err := binary.Read(reader, binary.BigEndian, &strLen); err != nil {
		return nil, err
	}
	if strLen > MaxChannelNameLength {
		return nil, fmt.Errorf("string length too large: %d > %d", strLen, MaxChannelNameLength)
	}
	buf := make([]byte, strLen)
	if n, err := io.ReadFull(reader, buf); err != nil {
		return nil, err
	} else if n != int(strLen) {
		return nil, fmt.Errorf("string is not fully received")
	}
	return buf, nil
}

func writeFrame(frame *Frame, writer io.Writer) error {
	if err := binary.Write(writer, binary.BigEndian, frame.Type); err != nil {
		return err
	}
	if err := binary.Write(writer, binary.BigEndian, frame.ConnectionID); err != nil {
		return err
	}
	return writeBytes([]byte(frame.Payload), writer)
}

func readFrame(frame *Frame, reader io.Reader) error {
	if err := binary.Read(reader, binary.BigEndian, &frame.Type); err != nil {
		return err
	}
	if err := binary.Read(reader, binary.BigEndian, &frame.ConnectionID); err != nil {
		return err
	}
	channelBytes, err := readBytes(reader)
	if err != nil {
		return err
	}
	frame.Payload = string(channelBytes)
	if frame.Type == proto.Close {
		if len(frame.Payload) == 0 {
			return io.EOF
		}
		return fmt.Errorf("connection closed: %s", frame.Payload)
	}
	return nil
}
