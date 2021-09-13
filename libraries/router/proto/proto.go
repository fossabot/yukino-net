package proto

const (
	// Indicates the frame contains a dial request. Controlled by Invoke ACL.
	Dial = byte(iota)
	// Indicates the frame contains a listen request. Controlled by Listen ACL.
	Listen = byte(iota)
	// Indicates the frame contains a bridge request. Controlled by Listen ACL.
	// This request should contain a connection ID for the server to set a bridge betwen a dial request.
	Bridge = byte(iota)
	// Indicates the frame is just for a ping. No ACL action specific control.
	Nop = byte(iota)
	// Indicates the connection is closed. No ACL action specific control.
	Close = byte(iota)
)
