package proto

const (
	Dial   = byte(iota)
	Listen = byte(iota)
	Bridge = byte(iota)
	Nop    = byte(iota)
	Close  = byte(iota)
)
