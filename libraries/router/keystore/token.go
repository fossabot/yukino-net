package keystore

import (
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"regexp"
	"sync"
	"time"
)

const (
	// UndefinedACL indicates that the control rule is undefined.
	// If all rules are undefined, KeyStore will reject this request.
	UndefinedACL = iota
	// Allow indicates that this policy is allowed.
	Allow = iota
	// Deny indicates that this policy is denied.
	Deny = iota

	// InvokeAction indicates invoke type of requests.
	InvokeAction = iota
	// ListenAction indicates listen type of requests.
	ListenAction = iota
)

// ACLRule stores an access control rule to all channels matched with `ChannelRegexp`.
type ACLRule struct {
	// Controls the ability to listen to a channel.
	ListenControl int `json:"listen" default:"0"`
	// Controls the ability to invoke services on a channel.
	InvokeControl int `json:"invoke" default:"0"`
	// Specifies the regular expression matching rules.
	ChannelRegexp string `json:"channel_regexp"`
}

// SessionKey represents the property of the key.
type SessionKey struct {
	// Expiration time of the key.
	Expire time.Time `json:"expire"`
	// If there are multiple matching rules, takes the later one in the array.
	Rules []ACLRule `json:"rules"`
	// ID of this key, just for identification.
	ID string `json:"id"`
	// Description of this key.
	Description string `json:"description"`
}

// KeyStore - A structure to store a set of keys.
// This structure is thread-compatible.
type KeyStore struct {
	mu    *sync.RWMutex
	Table map[string]*SessionKey `json:"table"`
	cache map[string]string      `json:"-"`
}

// Save dumps all configuration to the disk in JSON format WITHOUT any encryption.
func (store *KeyStore) Save(FileName string) error {
	store.mu.RLock()
	defer store.mu.RUnlock()
	data, err := json.MarshalIndent(*store, "", "    ")
	if err != nil {
		return err
	}
	return os.WriteFile(FileName, data, 0755)
}

// LoadKeyStore will load configuration from disk.
func LoadKeyStore(FileName string) (*KeyStore, error) {
	data, err := os.ReadFile(FileName)
	if err != nil {
		return nil, err
	}
	keyStore := &KeyStore{
		mu:    &sync.RWMutex{},
		Table: make(map[string]*SessionKey),
		cache: make(map[string]string),
	}
	if err := json.Unmarshal(data, keyStore); err != nil {
		return nil, err
	}
	return keyStore, nil
}

// CreateKeyStore initializes a key store in memory.
func CreateKeyStore() *KeyStore {
	return &KeyStore{
		mu:    &sync.RWMutex{},
		Table: make(map[string]*SessionKey),
		cache: make(map[string]string),
	}
}

// CleanUp serves as a garbage collection function that will remove all expired keys.
func (store *KeyStore) CleanUp() {
	expiredKeys := []string{}
	store.mu.Lock()
	defer store.mu.Unlock()

	for key, val := range store.Table {
		if time.Now().After(val.Expire) {
			expiredKeys = append(expiredKeys, key)
		}
	}

	for _, key := range expiredKeys {
		delete(store.Table, key)
	}

	store.cache = make(map[string]string)
}

// UpdateKey updates the property of the Key, will create a new entry if Key does not exist.
func (store *KeyStore) UpdateKey(Key []byte, property SessionKey) {
	hashkey := HashKey(Key)
	store.mu.Lock()
	defer store.mu.Unlock()
	store.Table[hashkey] = &property
}

// RegisterKey registers a key into the KeyStore. Returns error if key exists or is too short.
func (store *KeyStore) RegisterKey(Key []byte, property SessionKey) error {
	hashkey := HashKey(Key)
	store.mu.Lock()
	defer store.mu.Unlock()

	if _, ok := store.Table[hashkey]; ok {
		return fmt.Errorf("key already registered")
	}
	for _, val := range store.Table {
		if property.ID == val.ID {
			return fmt.Errorf("key ID already registered")
		}
	}
	store.Table[hashkey] = &property
	return nil
}

// lookupHashKey returns nil if key is not registered, or the property of the key if found.
func (store *KeyStore) lookupHashKey(key string) *SessionKey {
	store.mu.RLock()
	defer store.mu.RUnlock()
	if property, exist := store.Table[key]; exist && property.Expire.After(time.Now()) {
		tmp := *property
		return &tmp
	}
	return nil
}

func shouldAllow(requestType int, channelName string, rules []ACLRule) bool {
	allowed := UndefinedACL
	for _, rule := range rules {
		matched, err := regexp.MatchString(rule.ChannelRegexp, channelName)
		if err != nil {
			log.Printf("Warning: Rule %s has error: %s, skipped this rule", rule.ChannelRegexp, err.Error())
			continue
		}
		if matched {
			switch requestType {
			case InvokeAction:
				allowed = rule.InvokeControl
			case ListenAction:
				allowed = rule.ListenControl
			}
		}
	}
	return allowed == Allow
}

// HashKey returns a hashed salted key, which will store on disk.
func HashKey(key []byte) string {
	hash := sha512.Sum512(key)
	return base64.RawStdEncoding.EncodeToString(hash[:])
}

// GetSessionKey returns the matched key property.
func (store *KeyStore) GetSessionKey(key []byte) *SessionKey {
	store.mu.Lock()
	var realKey string
	serialKey := base64.RawStdEncoding.EncodeToString(key)
	cachedKey, ok := store.cache[serialKey]
	if ok {
		realKey = cachedKey
	} else {
		realKey = HashKey(key)
	}
	store.cache[serialKey] = realKey
	store.mu.Unlock()
	keyProperty := store.lookupHashKey(realKey)
	if keyProperty == nil {
		return nil
	}
	if time.Now().After(keyProperty.Expire) {
		return nil
	}
	return keyProperty
}

// GetExpireTime returns the expiration time of the key, if key is not registered, a past time will be returned.
func (store *KeyStore) GetExpireTime(key []byte) time.Time {
	if keyProperty := store.GetSessionKey(key); keyProperty != nil {
		return keyProperty.Expire
	}
	return time.Now().Add(-time.Second)
}

// CheckPermission checks the permission of the header for given request type acting on the requested channel.
// We only examine the first key within the `header`.
func (store *KeyStore) CheckPermission(requestType int, channelName string, key []byte) bool {
	if sessionKey := store.GetSessionKey(key); sessionKey != nil {
		return shouldAllow(requestType, channelName, sessionKey.Rules)
	}
	return false
}

// GenerateKeyAndRegister generates a key and registers into the table.
func (store *KeyStore) GenerateKeyAndRegister(name string, rules []ACLRule, duration time.Duration) string {
	p := make([]byte, 64)
	if _, err := rand.Read(p); err != nil {
		log.Fatalf("cannot generate keys: %v", err)
	}
	if err := store.RegisterKey(p, SessionKey{
		Expire: time.Now().Add(duration),
		Rules:  rules,
		ID:     name,
	}); err != nil {
		log.Fatalf("cannot register key: %v", err)
	}
	return base64.RawStdEncoding.EncodeToString(p)
}
