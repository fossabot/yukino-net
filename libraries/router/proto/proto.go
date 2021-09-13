package proto

const (
	// Dial indicates the frame contains a dial request. Controlled by Invoke ACL.
	Dial = byte(iota)
	// Listen indicates the frame contains a listen request. Controlled by Listen ACL.
	Listen = byte(iota)
	// Bridge indicates the frame contains a bridge request. Controlled by Listen ACL.
	// This request should contain a connection ID for the server to set a bridge betwen a dial request.
	Bridge = byte(iota)
	// Nop indicates the frame is just for a ping. No ACL action specific control.
	Nop = byte(iota)
	// Close indicates the connection is closed. No ACL action specific control.
	Close = byte(iota)
)
