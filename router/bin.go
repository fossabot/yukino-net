package router

import (
	"encoding/binary"
	"fmt"
	"io"
)

const MaxChannelNameLength = 256

func writeString(message *string, writer io.Writer) error {
	if err := binary.Write(writer, binary.BigEndian, uint16(len(*message))); err != nil {
		return err
	}
	if n, err := writer.Write([]byte(*message)); err != nil {
		return err
	} else if n != len(*message) {
		return fmt.Errorf("string not fully write")
	}
	return nil
}

func readString(reader io.Reader) (string, error) {
	var strLen uint16
	if err := binary.Read(reader, binary.BigEndian, &strLen); err != nil {
		return "", err
	}
	if strLen > MaxChannelNameLength {
		return "", fmt.Errorf("string length too large: %d > %d", strLen, MaxChannelNameLength)
	}
	buf := make([]byte, strLen)
	if n, err := io.ReadFull(reader, buf); err != nil {
		return "", err
	} else if n != int(strLen) {
		return "", fmt.Errorf("string is not fully received")
	}
	return string(buf), nil
}

func writeFrame(frame *RouterFrame, writer io.Writer) error {
	writer.Write([]byte{frame.Type})
	switch frame.Type {
	case Nop:
	case Close:
	case Listen:
		return writeString(&frame.Channel, writer)
	case Bridge:
		return writeString(&frame.Channel, writer)
	case Dial:
		return writeString(&frame.Channel, writer)
	}
	return nil
}

func readFrame(frame *RouterFrame, reader io.Reader) error {
	buf := make([]byte, 1)
	if n, err := io.ReadFull(reader, buf); err != nil {
		return err
	} else if n != 1 {
		return fmt.Errorf("cannot read control byte")
	}
	frame.Type = buf[0]
	var err error
	switch frame.Type {
	case Nop:
		frame.Channel = ""
	case Close:
		frame.Channel = ""
	case Listen:
		frame.Channel, err = readString(reader)
		if err != nil {
			return err
		}
	case Bridge:
		frame.Channel, err = readString(reader)
		if err != nil {
			return err
		}
	case Dial:
		frame.Channel, err = readString(reader)
		if err != nil {
			return err
		}
	}
	return nil
}
