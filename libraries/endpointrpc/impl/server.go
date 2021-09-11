package impl

import (
	"context"
	"log"
	"os/exec"

	"github.com/google/shlex"
	pb "github.com/xpy123993/yukino-net/libraries/endpointrpc/proto"
	"google.golang.org/grpc/codes"
	_ "google.golang.org/grpc/encoding/gzip"
	"google.golang.org/grpc/status"
)

type EndPointServer struct {
	pb.UnimplementedEndpointServer

	ACL map[[32]byte]bool
}

func NewServer() *EndPointServer {
	return &EndPointServer{
		ACL: map[[32]byte]bool{},
	}
}

func NewServerWithACL(ACL [][32]byte) *EndPointServer {
	acl := make(map[[32]byte]bool)
	for _, nACL := range ACL {
		acl[nACL] = true
	}
	return &EndPointServer{
		ACL: acl,
	}
}

func (server *EndPointServer) ShellProxy(ctx context.Context, request *pb.ShellProxyRequest) (*pb.ShellProxyResponse, error) {
	if err := Verify(server.ACL, request); err != nil {
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}
	commandSeq, err := shlex.Split(request.GetCommand())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "error while interpreting command: %v", err)
	}
	commandCtx, cancelFn := context.WithDeadline(ctx, request.GetDeadline().AsTime())
	defer cancelFn()
	log.Printf("executing command: %s", request.GetCommand())
	cmd := exec.CommandContext(commandCtx, commandSeq[0], commandSeq[1:]...)
	result, err := cmd.CombinedOutput()
	if err != nil {
		return nil, status.Errorf(codes.Aborted, "error while executing the command: %v", err)
	}
	response := pb.ShellProxyResponse{
		Message: string(result),
	}
	return &response, nil
}
