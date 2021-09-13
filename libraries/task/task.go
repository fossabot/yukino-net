// Package task is an RPC library to execute shell command with ed25519 authentication.
package task

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"os/exec"
	"time"

	"github.com/google/shlex"
	"github.com/xpy123993/yukino-net/libraries/common"
)

// CreateShellCommandInterpreter returns an interpreter that will use the `TaskName` template, and substitute all params.
func CreateShellCommandInterpreter(BaseCommand string) CommandInterpreter {
	return func(ctx context.Context, command Command) ([]byte, error) {
		commandSeq, err := shlex.Split(command.Command)
		if err != nil {
			return nil, err
		}
		var cmd *exec.Cmd
		if len(BaseCommand) > 0 {
			cmd = exec.CommandContext(ctx, BaseCommand, commandSeq...)
		} else {
			cmd = exec.CommandContext(ctx, commandSeq[0], commandSeq[1:]...)
		}
		return cmd.CombinedOutput()
	}
}

// Response is a structure to store a command execution result.
type Response struct {
	// Task Identifier, will be the same to the request.
	TaskID string `json:"taskID"`
	// The timestmap of the command to be done.
	Finish time.Time `json:"finish"`
	// Result of the task.
	Data []byte `json:"data"`
	// IsError indicates if this response is in error state.
	IsError bool `json:"is_error"`
	// ErrorMessage represents an error state if not nil.
	ErrorMessage string `json:"error"`
}

// Error returns an error state parsed from Response, if it is succeed, returns nil.
func (response *Response) Error() error {
	if response.IsError {
		return fmt.Errorf(response.ErrorMessage)
	}
	return nil
}

// Encode hides the marshal detail to other layer.
func (request *Request) Encode(writer io.Writer) error {
	return common.WriteWithZlib(writer, *request)
}

// Encode hides the marshal detail to other layer.
func (response *Response) Encode(writer io.Writer) error {
	return common.WriteWithZlib(writer, *response)
}

// Decode hides the unmarshal detail to other layer.
func (request *Request) Decode(reader io.Reader) error {
	return common.ReadWithZlib(reader, request)
}

// Decode hides the unmarshal detail to other layer.
func (response *Response) Decode(reader io.Reader) error {
	return common.ReadWithZlib(reader, response)
}

// Command is a structure to store a command to be executed.
type Command struct {
	// Name of the task to be executed.
	Command string `json:"name"`
	// For security purpose, client will drop the request if the deadline is passed.
	Deadline time.Time `json:"expires"`

	// If specified, once the command is done.
	// `TaskResult` will be sent to `ReceiverChannel` with given `TaskID`.
	TaskID string `json:"taskID"`
}

// Request is a structure to store a task request.
type Request struct {
	// Actual command to be executed.
	Command Command `json:"command"`
	// (ed25519) The public key of the sender.
	SenderPubKey string `json:"sender"`
	// (ed25519) The signature of the data
	SenderSign string `json:"sign"`
}

// DoneFunction is a callback with TaskResponse as its parameter.
type DoneFunction func(*Response)

// CommandInterpreter contains the implementation of a command interpreter.
type CommandInterpreter func(context.Context, Command) ([]byte, error)

// CommandServiceContext stores the context of a task. MUST be initialized with CreateAPPServerContext function.
type CommandServiceContext struct {
	// Permission check ACL.
	ACL map[string]bool
	// Tokens to limit maximum inflight async calls.
	tokens chan struct{}
	// Task interpreter
	interpreter CommandInterpreter
}

func makeResponse(taskID string, message []byte, err error) *Response {
	response := Response{
		TaskID:  taskID,
		Finish:  time.Now(),
		Data:    message,
		IsError: err != nil,
	}
	if response.IsError {
		response.ErrorMessage = err.Error()
	}
	return &response
}

// CheckPermission will enforce permission policy in `ACL` and returns any permission error encountered.
//   - If `ACL` empty, permission check will pass.
//   - If `ACL` is not empty, this function will check:
//     - 1. request has a sender, and sender is in the ACL.
//     - 2. request has a timestamp, and it is not expired.
//     - 3. request has a valid ed25519 signature of `command` field.
func (request *Request) CheckPermission(ACL map[string]bool) error {
	if len(ACL) == 0 {
		return nil
	}
	if request.Command.Deadline.IsZero() {
		return fmt.Errorf("request doesn't contain a timestamp for authentication")
	}
	if time.Now().After(request.Command.Deadline) {
		return fmt.Errorf("request contains an expired timestamp")
	}
	if len(request.SenderPubKey) == 0 {
		return fmt.Errorf("request doesn't include a key to be verified")
	}
	if base64.RawURLEncoding.DecodedLen(len(request.SenderPubKey)) != 32 || base64.RawURLEncoding.DecodedLen(len(request.SenderSign)) != 64 {
		return fmt.Errorf("invalid request")
	}
	if _, exist := ACL[request.SenderPubKey]; !exist {
		return fmt.Errorf("specified key doesn't have permission to execute the task")
	}
	pubkey, err := base64.RawURLEncoding.DecodeString(request.SenderPubKey)
	if err != nil {
		return fmt.Errorf("invalid pubkey")
	}
	signature, err := base64.RawURLEncoding.DecodeString(request.SenderSign)
	if err != nil {
		return fmt.Errorf("invalid signature")
	}
	data, err := json.Marshal(request.Command)
	if err != nil {
		return fmt.Errorf("internal error: cannot serialize data to be verified")
	}
	if ed25519.Verify(pubkey, data, signature) {
		return nil
	}
	return fmt.Errorf("invalid signature: verification failed")
}

// Sign will populate `SenderPubKey` and `SenderSign` fields.
// Any modifications on `Command` and `Metadata` fields require another Sign call.
func (request *Request) Sign(priv ed25519.PrivateKey) error {
	if request.Command.Deadline.IsZero() {
		return fmt.Errorf("deadline field must be set for authentication")
	}
	if time.Now().After(request.Command.Deadline) {
		return fmt.Errorf("deadline specified in Command field is already passed")
	}
	data, err := json.Marshal(request.Command)
	if err != nil {
		return err
	}

	request.SenderPubKey = base64.RawURLEncoding.EncodeToString([]byte(priv)[32:])
	request.SenderSign = base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, data))
	return nil
}

// CreateServerContext initializes a TaskContext object.
func CreateServerContext(ACL []string, MaxInflights int, Interpreter CommandInterpreter) CommandServiceContext {
	ctx := CommandServiceContext{
		ACL:         make(map[string]bool),
		tokens:      make(chan struct{}, MaxInflights),
		interpreter: Interpreter,
	}
	for _, pubkey := range ACL {
		ctx.ACL[pubkey] = true
	}
	return ctx
}

// Execute is a blocking call that executes the command wrapped in `TaskCommand`.
// Returns OK if succeed, otherwise an error message.
func (ctx *CommandServiceContext) Execute(command *Command) ([]byte, error) {
	if ctx.interpreter == nil {
		return []byte{}, fmt.Errorf("interpreter not set up")
	}
	if command.Deadline.After(time.Now()) {
		execContext, cancelFn := context.WithDeadline(context.Background(), command.Deadline)
		defer cancelFn()
		return ctx.interpreter(execContext, *command)
	}
	if command.Deadline.IsZero() {
		return ctx.interpreter(context.Background(), *command)
	}
	return []byte{}, fmt.Errorf("precondition: command timeout before executing")
}

// FullFillRequest is a blocking call to take a request to perform permission check and fulfill the request.
func FullFillRequest(ctx *CommandServiceContext, request *Request) *Response {
	if err := request.CheckPermission(ctx.ACL); err != nil {
		time.Sleep(2 * time.Duration(rand.Float32()) * time.Second)
		return makeResponse(request.Command.TaskID, []byte{}, fmt.Errorf("permission error: %s", err.Error()))
	}
	data, err := ctx.Execute(&request.Command)
	return makeResponse(request.Command.TaskID, data, err)
}

// FullFillRequestWithCallback is a non-blocking call to take a request to perform permission check and fulfill the request.
// Its parallelism can be controlled by APPServerContext option `MaxInFlights`.
func FullFillRequestWithCallback(ctx *CommandServiceContext, request *Request, done DoneFunction) {
	ctx.tokens <- struct{}{}
	go func() {
		defer func() { <-ctx.tokens }()
		done(FullFillRequest(ctx, request))
	}()
}
