package task_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xpy123993/yukino-net/libraries/task"
)

var (
	pubkey  []byte
	privkey []byte
)

func fakeCallback(ctx context.Context, command task.Command) ([]byte, error) {
	return nil, nil
}

func generateARequestOrFail(t *testing.T, deadline *time.Time, privkey []byte) (task.Request, []byte) {
	request := task.Request{
		Command: task.Command{
			Command: "fake task",
			TaskID:  "fake_id",
		},
	}
	if deadline != nil {
		request.Command.Deadline = *deadline
	}
	data, err := json.Marshal(request.Command)
	if err != nil {
		t.Error(err)
	}
	if len(privkey) > 0 {
		request.SenderPubKey = base64.RawURLEncoding.EncodeToString(privkey[32:])
		request.SenderSign = base64.RawURLEncoding.EncodeToString(ed25519.Sign(privkey, data))
	}
	return request, data
}

func TestSignVerifySuccess(t *testing.T) {
	future := time.Now().Add(time.Hour)
	request, _ := generateARequestOrFail(t, &future, privkey)
	if err := request.CheckPermission(map[string]bool{base64.RawURLEncoding.EncodeToString(pubkey): true}); err != nil {
		t.Errorf("error unexpected: %s", err.Error())
		t.FailNow()
	}
}

func TestSignCanFailWithEmptyDeadline(t *testing.T) {
	request, _ := generateARequestOrFail(t, nil, nil)
	if err := request.Sign(privkey); err != nil {
		if !strings.Contains(err.Error(), "deadline field must be set for authentication") {
			t.Errorf("error unexpected: %s", err.Error())
			t.FailNow()
		}
	} else {
		t.Errorf("expect to return an error")
	}
}

func TestSignCanFailWithPastDeadline(t *testing.T) {
	past := time.Now().Add(-time.Hour)
	request, _ := generateARequestOrFail(t, &past, nil)
	if err := request.Sign(privkey); err != nil {
		if !strings.Contains(err.Error(), "already passed") {
			t.Errorf("error unexpected: %s", err.Error())
			t.FailNow()
		}
	} else {
		t.Errorf("expect to return an error")
	}
}

func TestVerifyEmpty(t *testing.T) {
	future := time.Now().Add(time.Hour)
	request, _ := generateARequestOrFail(t, &future, nil)
	if err := request.CheckPermission(map[string]bool{}); err != nil {
		t.Error(err)
	}
	if err := request.Sign(privkey); err != nil {
		t.Error(err)
	}
	if err := request.CheckPermission(map[string]bool{}); err != nil {
		t.Error(err)
	}
}

func expectFail(t *testing.T, request *task.Request, pub []byte, errMessage string) {
	if err := request.CheckPermission(map[string]bool{base64.RawURLEncoding.EncodeToString(pub): true}); err == nil {
		t.Error("expect an error here")
	} else if !strings.Contains(err.Error(), errMessage) {
		t.Errorf("unexpected error: %s", err.Error())
	}
}

func TestVerifyCanFailWithModifiedContent(t *testing.T) {
	future := time.Now().Add(time.Hour)
	request, _ := generateARequestOrFail(t, &future, privkey)
	request.Command.Command = "changed"
	expectFail(t, &request, pubkey, "verification failed")
}

func TestVerifyFailOnNoKeyToVerify(t *testing.T) {
	future := time.Now().Add(time.Hour)
	request, _ := generateARequestOrFail(t, &future, privkey)
	request.SenderPubKey = ""
	expectFail(t, &request, pubkey, "doesn't include a key")
}

func TestVerifyFailOnDeadlineExpired(t *testing.T) {
	past := time.Now().Add(-time.Hour)
	request, _ := generateARequestOrFail(t, &past, privkey)
	expectFail(t, &request, pubkey, "contains an expired timestamp")
}

func TestVerifyFailOnEmptyDeadline(t *testing.T) {
	request, _ := generateARequestOrFail(t, nil, privkey)
	expectFail(t, &request, pubkey, "doesn't contain")
}

func TestVerifyFailOnPubkeyNotAllowed(t *testing.T) {
	future := time.Now().Add(time.Hour)
	request, _ := generateARequestOrFail(t, &future, privkey)
	expectFail(t, &request, []byte("abc"), "doesn't have permission")
}

func TestTaskFailedOnDeadlineExceeded(t *testing.T) {
	command := task.Command{
		Command:  "sleep 1",
		Deadline: time.Now().Add(50 * time.Millisecond),
	}
	ctx := task.CreateServerContext([]string{}, 1, task.CreateShellCommandInterpreter(""))
	response, err := ctx.Execute(&command)
	if err == nil || !strings.Contains(err.Error(), "killed") {
		t.Errorf("unexpected result: %s", response)
	}
}

func TestTaskSucceedWithoutDeadline(t *testing.T) {
	command := task.Command{
		Command: "some random string",
	}
	ctx := task.CreateServerContext([]string{}, 1, task.CreateShellCommandInterpreter("echo"))
	response, err := ctx.Execute(&command)
	if err != nil || !strings.Contains(string(response), "some random string") {
		t.Errorf("unexpected result: %s", response)
	}
}

func TestTaskSucceedWithDeadline(t *testing.T) {
	command := task.Command{
		Command:  "some random string",
		Deadline: time.Now().Add(5 * time.Second),
	}
	ctx := task.CreateServerContext([]string{}, 1, task.CreateShellCommandInterpreter("echo"))
	response, err := ctx.Execute(&command)
	if err != nil || !strings.Contains(string(response), "some random string") {
		t.Errorf("unexpected result: %s", response)
	}
}

func TestProcessTaskRequestReturnsValidationError(t *testing.T) {
	ctx := task.CreateServerContext([]string{"random_token"}, 1, nil)
	request := task.Request{
		Command: task.Command{
			Command:  "some task",
			Deadline: time.Now().Add(time.Minute),
		},
		SenderPubKey: "some key",
	}
	response := task.FullFillRequest(&ctx, &request)
	if !response.IsError || !strings.Contains(response.ErrorMessage, "permission error") {
		t.Errorf("unexpected result: %v", response)
	}
}

func TestProcessTaskRequestSuceedWithDeadline(t *testing.T) {
	ctx := task.CreateServerContext([]string{base64.RawURLEncoding.EncodeToString(pubkey)}, 1, task.CreateShellCommandInterpreter("echo"))
	request := task.Request{
		Command: task.Command{
			Command:  "hello world",
			TaskID:   "task_id",
			Deadline: time.Now().Add(time.Minute),
		},
	}
	if err := request.Sign(privkey); err != nil {
		t.Error(err)
	}

	response := task.FullFillRequest(&ctx, &request)
	if !strings.Contains(string(response.Data), "hello world") {
		t.Errorf("unexpected result: %v", response)
	}
	if response.TaskID != "task_id" {
		t.Errorf("task ID mismatched")
	}
}

func TestProcessTaskASyncRequestSuceedWithDeadline(t *testing.T) {
	ctx := task.CreateServerContext([]string{base64.RawURLEncoding.EncodeToString(pubkey)}, 1, task.CreateShellCommandInterpreter("echo"))
	request := task.Request{
		Command: task.Command{
			Command:  "hello world",
			Deadline: time.Now().Add(time.Minute),
		},
	}
	if err := request.Sign(privkey); err != nil {
		t.Error(err)
	}

	done := make(chan struct{})
	task.FullFillRequestWithCallback(&ctx, &request, task.DoneFunction(func(response *task.Response) {
		defer close(done)
		if !strings.Contains(string(response.Data), "hello world") {
			t.Errorf("unexpected result: %v", response)
		}
	}))
	<-done
}

func prepareBenchmarkRequests(b *testing.B, auth bool) (task.CommandServiceContext, []task.Request) {
	acl := []string{}
	if auth {
		acl = make([]string, b.N)
	}
	requests := make([]task.Request, b.N)

	for i := 0; i < b.N; i++ {
		requests[i] = task.Request{
			Command: task.Command{
				Command:  "echo",
				Deadline: time.Now().Add(time.Minute),
			},
		}
		if auth {
			pub, priv, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				b.Error(err)
			}
			acl[i] = base64.RawURLEncoding.EncodeToString(pub)
			if err := requests[i].Sign(priv); err != nil {
				b.Error(err)
			}
		}
	}

	return task.CreateServerContext(acl, 1, task.CommandInterpreter(fakeCallback)), requests
}

func BenchmarkProcessTaskWithAuthentication(b *testing.B) {
	ctx, requests := prepareBenchmarkRequests(b, true)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		task.FullFillRequest(&ctx, &requests[i])
	}
}

func BenchmarkProcessTaskWithoutAuthentication(b *testing.B) {
	ctx, requests := prepareBenchmarkRequests(b, false)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		task.FullFillRequest(&ctx, &requests[i])
	}
}

func BenchmarkProcessTaskASyncWithAuthentication(b *testing.B) {
	ctx, requests := prepareBenchmarkRequests(b, true)
	b.ResetTimer()

	wg := sync.WaitGroup{}
	for i := 0; i < b.N; i++ {
		wg.Add(1)
		task.FullFillRequestWithCallback(&ctx, &requests[i], task.DoneFunction(func(response *task.Response) {
			wg.Done()
		}))
	}
	wg.Wait()
}

func BenchmarkProcessTaskASyncWithoutAuthentication(b *testing.B) {
	ctx, requests := prepareBenchmarkRequests(b, false)
	b.ResetTimer()

	wg := sync.WaitGroup{}
	for i := 0; i < b.N; i++ {
		wg.Add(1)
		task.FullFillRequestWithCallback(&ctx, &requests[i], task.DoneFunction(func(response *task.Response) {
			wg.Done()
		}))
	}
	wg.Wait()
}

func TestMain(m *testing.M) {
	var err error
	pubkey, privkey, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	os.Exit(m.Run())
}
