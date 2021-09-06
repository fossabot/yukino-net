package main

import _ "embed"

//go:embed x509/ca.crt
var ca []byte

//go:embed x509/server.crt
var crt []byte

//go:embed x509/server.key
var key []byte

const ServerName = "message.yukino.app"
