package cmd

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/xpy123993/yukino-net/libraries/endpointrpc/impl"
	pb "github.com/xpy123993/yukino-net/libraries/endpointrpc/proto"
	"github.com/xpy123993/yukino-net/libraries/util"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/time/rate"
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

func InvokeEndPointShellProxyService(ctx context.Context, ConfigFile, Channel, Command string, PrivateKey string, timeout time.Duration) (string, error) {
	client, err := initializeEndPointClient(ctx, ConfigFile, Channel)
	if err != nil {
		return "", err
	}
	request := pb.ShellProxyRequest{
		Command:  Command,
		Deadline: timestamppb.New(time.Now().Add(timeout)),
	}
	if len(PrivateKey) > 0 {
		priv, err := base64.RawStdEncoding.DecodeString(PrivateKey)
		if err != nil {
			return "", fmt.Errorf("error while loading public key")
		}
		impl.Sign(priv, &request)
	}
	resp, err := client.ShellProxy(ctx, &request)
	if err != nil {
		return "", err
	}
	return resp.GetMessage(), nil
}

func StartEndPointService(ctx context.Context, ConfigFile, Channel string, ACL []string) error {
	listener, err := util.CreateListenerFromConfig(ConfigFile, Channel)
	if err != nil {
		return err
	}
	var server *impl.EndPointServer
	if len(ACL) > 0 {
		keys := make([][32]byte, len(ACL))
		for i, key := range ACL {
			rawKey, err := base64.RawStdEncoding.DecodeString(key)
			if err != nil {
				return fmt.Errorf("failed to extract public key: %v", err)
			}
			copy(keys[i][:], rawKey)
		}
		server = impl.NewServerWithACL(keys)
	} else {
		server = impl.NewServer()
	}
	rpcServer := grpc.NewServer()
	pb.RegisterEndpointServer(rpcServer, server)

	log.Printf("Starting EndPoint service on channel `%s`", Channel)
	return rpcServer.Serve(listener)
}

func GetHashToken(Token string) string {
	data, err := base64.RawURLEncoding.DecodeString(Token)
	if err != nil {
		return "invalid"
	}
	return base64.RawURLEncoding.EncodeToString(argon2.IDKey(data, []byte("yapp/net/salt"), 1, 64*1024, 4, 64))
}

func GenerateEd25519() {
	pub, priv, err := ed25519.GenerateKey(cryptorand.Reader)
	if err != nil {
		log.Fatalf("failed to generate key: %v", err)
	}
	fmt.Printf("Public Key: %s\nPrivate Key: %s\n", base64.RawStdEncoding.EncodeToString(pub), base64.RawStdEncoding.EncodeToString(priv))
}

func StartEndPointWebhook(ctx context.Context, ConfigFile, LocalAddr, HashToken string) error {
	limiter := rate.NewLimiter(3, 10)
	http.HandleFunc("/", func(rw http.ResponseWriter, r *http.Request) {
		if !limiter.Allow() {
			http.Error(rw, http.StatusText(http.StatusTooManyRequests), http.StatusTooManyRequests)
			return
		}
		channel := strings.TrimPrefix(r.RequestURI, "/")
		if len(channel) == 0 {
			time.Sleep(time.Duration(1+2*rand.Float32()) * time.Second)
			rw.WriteHeader(http.StatusBadRequest)
			return
		}
		if GetHashToken(r.Header.Get("EndPoint-Service-Token")) != HashToken {
			time.Sleep(time.Duration(1+2*rand.Float32()) * time.Second)
			rw.WriteHeader(http.StatusUnauthorized)
			return
		}
		InvokeEndPointShellProxyService(ctx, ConfigFile, channel, r.Header.Get("Command"), r.Header.Get("Private-Key"), 5*time.Second)
	})
	return http.ListenAndServe(LocalAddr, nil)
}

func GenerateToken() error {
	p := make([]byte, 64)
	_, err := cryptorand.Read(p)
	if err != nil {
		return err
	}
	token := base64.RawURLEncoding.EncodeToString(p)
	hashtoken := GetHashToken(token)
	fmt.Printf("Token (EndPoint-Service-Token): %s\nWebHook HashToken: %s\n", token, hashtoken)
	return nil
}
