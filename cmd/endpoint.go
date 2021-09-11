package cmd

import (
	"context"
	"log"
	"net"
	"time"

	"github.com/xpy123993/yukino-net/libraries/endpointrpc/impl"
	pb "github.com/xpy123993/yukino-net/libraries/endpointrpc/proto"
	"github.com/xpy123993/yukino-net/libraries/util"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func initializeEndPointClient(ctx context.Context, configFile string, channel string) (pb.EndpointClient, error) {
	routerClient, err := util.CreateClientFromConfig(configFile)
	if err != nil {
		return nil, err
	}

	rpcClient, err := grpc.DialContext(ctx, channel, grpc.WithContextDialer(func(c context.Context, s string) (net.Conn, error) {
		return routerClient.Dial(s)
	}), grpc.WithInsecure())
	if err != nil {
		return nil, err
	}
	return pb.NewEndpointClient(rpcClient), nil
}

func InvokeEndPointShellProxyService(ctx context.Context, ConfigFile, Channel, Command string, timeout time.Duration) (string, error) {
	client, err := initializeEndPointClient(ctx, ConfigFile, Channel)
	if err != nil {
		return "", err
	}
	resp, err := client.ShellProxy(ctx, &pb.ShellProxyRequest{
		Command:  Command,
		Deadline: timestamppb.New(time.Now().Add(timeout)),
	})
	if err != nil {
		return "", err
	}
	return resp.GetMessage(), nil
}

func StartEndPointService(ctx context.Context, ConfigFile, Channel string) error {
	listener, err := util.CreateListenerFromConfig(ConfigFile, Channel)
	if err != nil {
		return err
	}
	rpcServer := grpc.NewServer()
	pb.RegisterEndpointServer(rpcServer, impl.NewServer())

	log.Printf("Starting EndPoint service on channel `%s`", Channel)
	return rpcServer.Serve(listener)
}
