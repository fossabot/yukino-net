package keystore_test

import (
	"fmt"
	"log"
	"math/rand"
	"path"
	"testing"
	"time"

	"github.com/xpy123993/router/router/keystore"
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

func checkPermission(store *keystore.KeyStore, key []byte, channel string, invokeControl bool, invokeListen bool) error {
	if code := store.CheckPermission(keystore.InvokeAction, channel, key); code != invokeControl {
		return fmt.Errorf("invoke permission mismatched: (real) %v vs (expected) %v", code, invokeControl)
	}
	if code := store.CheckPermission(keystore.ListenAction, channel, key); code != invokeListen {
		return fmt.Errorf("invoke permission mismatched: (real) %v vs (expected) %v", code, invokeListen)
	}
	return nil
}

func initializeKeyStoreWithUnExpiredKey(invokeControl int, listenControl int, channelRegexp string) ([]byte, *keystore.KeyStore) {
	keyStore := keystore.CreateKeyStore()
	key := randomBytes(32)
	keyStore.RegisterKey(key, keystore.SessionKey{
		Expire: time.Now().Add(time.Hour),
		Rules: []keystore.ACLRule{
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
	key, keyStore := initializeKeyStoreWithUnExpiredKey(keystore.Allow, keystore.Deny, ".*")
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
	_, keyStore := initializeKeyStoreWithUnExpiredKey(keystore.Allow, keystore.Allow, ".*")
	if err := checkPermission(keyStore, randomBytes(32), "test", false, false); err != nil {
		t.Error(err)
	}
}

func TestAuthForListenOnlyKey(t *testing.T) {
	key, keyStore := initializeKeyStoreWithUnExpiredKey(keystore.UndefinedACL, keystore.Allow, ".*")
	if err := checkPermission(keyStore, key, "test", false, true); err != nil {
		t.Error(err)
	}
	key, keyStore = initializeKeyStoreWithUnExpiredKey(keystore.Deny, keystore.Allow, ".*")
	if err := checkPermission(keyStore, key, "test", false, true); err != nil {
		t.Error(err)
	}
}

func TestAuthForInvokeOnlyKey(t *testing.T) {
	key, keyStore := initializeKeyStoreWithUnExpiredKey(keystore.Allow, keystore.UndefinedACL, ".*")
	if err := checkPermission(keyStore, key, "test", true, false); err != nil {
		t.Error(err)
	}
	key, keyStore = initializeKeyStoreWithUnExpiredKey(keystore.Allow, keystore.Deny, ".*")
	if err := checkPermission(keyStore, key, "test", true, false); err != nil {
		t.Error(err)
	}
}

func TestAuthForChannelMismatchedKey(t *testing.T) {
	key, keyStore := initializeKeyStoreWithUnExpiredKey(keystore.Allow, keystore.Allow, "test")
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
	key, keyStore := initializeKeyStoreWithUnExpiredKey(keystore.Allow, keystore.Allow, "test")
	if err := checkPermission(keyStore, key, "test", true, true); err != nil {
		t.Error(err)
	}
	keyStore.Table[keystore.HashKey(key)].Expire = time.Now().Add(-time.Hour)
	if err := checkPermission(keyStore, key, "test", false, false); err != nil {
		t.Error(err)
	}
}

func TestAuthLoadSave(t *testing.T) {
	key, oldKeyStore := initializeKeyStoreWithUnExpiredKey(keystore.Allow, keystore.Deny, "test")
	configFile := path.Join(t.TempDir(), "auth.json")
	if err := oldKeyStore.Save(configFile); err != nil {
		t.Error(err)
	}
	keyStore, err := keystore.LoadKeyStore(configFile)
	if err != nil {
		t.Error(err)
	}
	if err := checkPermission(keyStore, key, "test", true, false); err != nil {
		t.Error(err)
	}
}

func TestAuthCleanUp(t *testing.T) {
	key, keyStore := initializeKeyStoreWithUnExpiredKey(keystore.Allow, keystore.Deny, "test")
	keyStore.Table[keystore.HashKey(key)].Expire = time.Now().Add(-time.Hour)
	keyStore.CleanUp()
	if len(keyStore.Table) != 0 {
		t.Error()
	}
}

func TestNoPlainTokenStored(t *testing.T) {
	key, keyStore := initializeKeyStoreWithUnExpiredKey(keystore.UndefinedACL, keystore.Allow, ".*")
	if _, ok := keyStore.Table[string(key)]; ok {
		t.Error("key is stored in plain text")
	}
}
