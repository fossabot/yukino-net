package impl

import (
	"crypto/rand"
	"fmt"

	pb "github.com/xpy123993/yukino-net/libraries/endpointrpc/proto"
	"golang.org/x/crypto/ed25519"
)

func dataField(request *pb.ShellProxyRequest) []byte {
	return []byte(fmt.Sprintf("[%s] %s", request.Deadline.String(), request.Command))
}

// Verify if the signature is valid.
func Verify(ACL map[[32]byte]bool, request *pb.ShellProxyRequest) error {
	if len(ACL) == 0 {
		return nil
	}
	if len(request.GetPublic()) != 32 {
		return fmt.Errorf("no public key received")
	}
	ed25519.GenerateKey(rand.Reader)
	buf := [32]byte{}
	copy(buf[:], request.GetPublic()[:32])
	if allow, exists := ACL[buf]; exists && allow {
		if ed25519.Verify(request.Public, dataField(request), request.Signature) {
			return nil
		}
	}
	return fmt.Errorf("unauthorized")
}

func Sign(priv []byte, request *pb.ShellProxyRequest) {
	request.Public = priv[32:]
	request.Signature = ed25519.Sign(priv, dataField(request))
}
