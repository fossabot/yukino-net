package router

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/xpy123993/router/libraries/router/proto"
)

const MaxChannelNameLength = 256

// RouterFrame is the packet using between Router.
type RouterFrame struct {
	Type         byte
	ConnectionID uint64
	Channel      string
}

var nopFrame = RouterFrame{Type: proto.Nop}

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

func writeFrame(frame *RouterFrame, writer io.Writer) error {
	if _, err := writer.Write([]byte{frame.Type}); err != nil {
		return err
	}
	if err := binary.Write(writer, binary.BigEndian, frame.ConnectionID); err != nil {
		return err
	}
	return writeBytes([]byte(frame.Channel), writer)
}

func readFrame(frame *RouterFrame, reader io.Reader) error {
	buf := make([]byte, 1)
	if n, err := io.ReadFull(reader, buf); err != nil {
		return err
	} else if n != 1 {
		return fmt.Errorf("cannot read control byte")
	}
	frame.Type = buf[0]
	if err := binary.Read(reader, binary.BigEndian, &frame.ConnectionID); err != nil {
		return err
	}
	channelBytes, err := readBytes(reader)
	if err != nil {
		return err
	}
	frame.Channel = string(channelBytes)
	return nil
}