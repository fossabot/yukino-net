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
}

func NewServer() *EndPointServer {
	return &EndPointServer{}
}

func (server *EndPointServer) ShellProxy(ctx context.Context, request *pb.ShellProxyRequest) (*pb.ShellProxyResponse, error) {
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
