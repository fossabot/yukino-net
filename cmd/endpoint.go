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

	"github.com/xpy123993/yukino-net/libraries/task"
	"github.com/xpy123993/yukino-net/libraries/util"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/time/rate"
)

func InvokeEndPointShellProxyService(ctx context.Context, ConfigFile []string, Channel, Command string, PrivateKey string, timeout time.Duration) (string, error) {
	request := task.Request{
		Command: task.Command{
			TaskName: Command,
			Deadline: time.Now().Add(timeout),
		},
	}
	if len(PrivateKey) > 0 {
		if base64.RawURLEncoding.DecodedLen(len(PrivateKey)) != 64 {
			return "", fmt.Errorf("[local] invalid private key: should be of 64 bytes, got %d bytes", base64.RawURLEncoding.DecodedLen(len(PrivateKey)))
		}
		priv, err := base64.RawURLEncoding.DecodeString(PrivateKey)
		if err != nil {
			return "", fmt.Errorf("[local] cannot parse private key: %v", err)
		}
		if err := request.Sign(priv); err != nil {
			return "", fmt.Errorf("[local] failed to sign request: %v", err)
		}
	}
	client, err := util.CreateClientFromConfig(ConfigFile)
	if err != nil {
		return "", err
	}
	conn, err := client.Dial(Channel)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	if err := request.Encode(conn); err != nil {
		return "", fmt.Errorf("[local] failed to send the request: %v", err)
	}
	response := task.Response{}
	if err := response.Decode(conn); err != nil {
		return "", fmt.Errorf("[local] failed to parse request: %v", err)
	}
	if response.IsError {
		return "", fmt.Errorf("[remote] %v", response.Error())
	}
	return string(response.Data), nil
}

func StartEndPointService(ctx context.Context, ConfigFile []string, Channel string, ACL []string, BaseCommand string) error {
	listener, err := util.CreateListenerFromConfig(ConfigFile, Channel)
	if err != nil {
		return fmt.Errorf("failed to listen on channel: %v", err)
	}
	serverContext := task.CreateServerContext(ACL, 4, task.CreateShellCommandInterpreter(BaseCommand))
	for ctx.Err() == nil {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		go func(client net.Conn) {
			defer conn.Close()
			request := &task.Request{}
			if err := request.Decode(client); err != nil {
				log.Printf("received invalid reuqest: %v", err)
				return
			}
			response := task.FullFillRequest(&serverContext, request)
			if err := response.Encode(client); err != nil {
				log.Printf("failed to respond to client: %v", err)
			}
		}(conn)
	}
	return ctx.Err()
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
	fmt.Printf("Public Key: %s\nPrivate Key: %s\n", base64.RawURLEncoding.EncodeToString(pub), base64.RawURLEncoding.EncodeToString(priv))
}

func StartEndPointWebhook(ctx context.Context, ConfigFile []string, LocalAddr, HashToken string) error {
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
		log.Printf("Forwarding command `%s` to channel `%s`.", r.Header.Get("Command"), channel)
		_, err := InvokeEndPointShellProxyService(ctx, ConfigFile, channel, r.Header.Get("Command"), r.Header.Get("Private-Key"), 5*time.Second)
		if err != nil {
			log.Printf("EndPoint service returns error: %v", err)
		}
	})
	log.Printf("Serving webhook at http://%s/", LocalAddr)
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
