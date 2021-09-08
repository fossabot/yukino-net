package token_test

import (
	"fmt"
	"log"
	"math/rand"
	"path"
	"testing"
	"time"

	"github.com/xpy123993/router/token"
)

const (
	NoPermission   = iota
	InvokeTestOnly = iota
	ListenTestOnly = iota
	InvokeAll      = iota
	ListenAll      = iota
	All            = iota
	AllButExpired  = iota
)

func randomBytes(n int) []byte {
	p := make([]byte, n)
	if _, err := rand.Read(p); err != nil {
		log.Fatalf("cannot generate random bytes for testing.")
	}
	return p
}

func checkPermission(store *token.KeyStore, key []byte, channel string, invokeControl bool, invokeListen bool) error {
	if code := store.CheckPermission(token.InvokeAction, channel, key); code != invokeControl {
		return fmt.Errorf("invoke permission mismatched: (real) %v vs (expected) %v", code, invokeControl)
	}
	if code := store.CheckPermission(token.ListenAction, channel, key); code != invokeListen {
		return fmt.Errorf("invoke permission mismatched: (real) %v vs (expected) %v", code, invokeListen)
	}
	return nil
}

func initializeKeyStoreWithUnExpiredKey(invokeControl int, listenControl int, channelRegexp string) ([]byte, *token.KeyStore) {
	keyStore := token.CreateKeyStore()
	key := randomBytes(32)
	keyStore.RegisterKey(key, token.SessionKey{
		Expire: time.Now().Add(time.Hour),
		Rules: []token.ACLRule{
			{
				InvokeControl: invokeControl,
				ListenControl: listenControl,
				ChannelRegexp: channelRegexp,
			},
		},
	})
	return key, keyStore
}

func TestUtilFunctionSanityCheck(t *testing.T) {
	key, keyStore := initializeKeyStoreWithUnExpiredKey(token.Allow, token.Deny, ".*")
	if err := checkPermission(keyStore, key, "test", true, false); err != nil {
		t.Error(err)
	}
	if err := checkPermission(keyStore, key, "test", true, true); err == nil {
		t.Error()
	}
	if err := checkPermission(keyStore, key, "test", false, true); err == nil {
		t.Error()
	}
	if err := checkPermission(keyStore, key, "test", false, false); err == nil {
		t.Error()
	}
}

func TestAuthFailedOnKeyNotExist(t *testing.T) {
	_, keyStore := initializeKeyStoreWithUnExpiredKey(token.Allow, token.Allow, ".*")
	if err := checkPermission(keyStore, randomBytes(32), "test", false, false); err != nil {
		t.Error(err)
	}
}

func TestAuthForListenOnlyKey(t *testing.T) {
	key, keyStore := initializeKeyStoreWithUnExpiredKey(token.UndefinedACL, token.Allow, ".*")
	if err := checkPermission(keyStore, key, "test", false, true); err != nil {
		t.Error(err)
	}
	key, keyStore = initializeKeyStoreWithUnExpiredKey(token.Deny, token.Allow, ".*")
	if err := checkPermission(keyStore, key, "test", false, true); err != nil {
		t.Error(err)
	}
}

func TestAuthForInvokeOnlyKey(t *testing.T) {
	key, keyStore := initializeKeyStoreWithUnExpiredKey(token.Allow, token.UndefinedACL, ".*")
	if err := checkPermission(keyStore, key, "test", true, false); err != nil {
		t.Error(err)
	}
	key, keyStore = initializeKeyStoreWithUnExpiredKey(token.Allow, token.Deny, ".*")
	if err := checkPermission(keyStore, key, "test", true, false); err != nil {
		t.Error(err)
	}
}

func TestAuthForChannelMismatchedKey(t *testing.T) {
	key, keyStore := initializeKeyStoreWithUnExpiredKey(token.Allow, token.Allow, "test")
	if err := checkPermission(keyStore, key, "test", true, true); err != nil {
		t.Error(err)
	}
	if err := checkPermission(keyStore, key, "unmatched", false, false); err != nil {
		t.Error(err)
	}
	if err := checkPermission(keyStore, key, "t", false, false); err != nil {
		t.Error(err)
	}
}

func TestAuthForExpiredKey(t *testing.T) {
	key, keyStore := initializeKeyStoreWithUnExpiredKey(token.Allow, token.Allow, "test")
	if err := checkPermission(keyStore, key, "test", true, true); err != nil {
		t.Error(err)
	}
	keyStore.Table[token.HashKey(key)].Expire = time.Now().Add(-time.Hour)
	if err := checkPermission(keyStore, key, "test", false, false); err != nil {
		t.Error(err)
	}
}

func TestAuthLoadSave(t *testing.T) {
	key, oldKeyStore := initializeKeyStoreWithUnExpiredKey(token.Allow, token.Deny, "test")
	configFile := path.Join(t.TempDir(), "auth.json")
	if err := oldKeyStore.Save(configFile); err != nil {
		t.Error(err)
	}
	keyStore, err := token.LoadKeyStore(configFile)
	if err != nil {
		t.Error(err)
	}
	if err := checkPermission(keyStore, key, "test", true, false); err != nil {
		t.Error(err)
	}
}

func TestAuthCleanUp(t *testing.T) {
	key, keyStore := initializeKeyStoreWithUnExpiredKey(token.Allow, token.Deny, "test")
	keyStore.Table[token.HashKey(key)].Expire = time.Now().Add(-time.Hour)
	keyStore.CleanUp()
	if len(keyStore.Table) != 0 {
		t.Error()
	}
}

func TestNoPlainTokenStored(t *testing.T) {
	key, keyStore := initializeKeyStoreWithUnExpiredKey(token.UndefinedACL, token.Allow, ".*")
	if _, ok := keyStore.Table[string(key)]; ok {
		t.Error("key is stored in plain text")
	}
}
