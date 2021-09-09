package main

import (
	"flag"
	"log"
	"time"

	"github.com/xpy123993/router/token"
)

var (
	tokenFile     = flag.String("token-file", "token.json", "Token file to edit")
	keyName       = flag.String("name", "", "The ID of the key")
	duration      = flag.Duration("duration", 180*24*time.Hour, "Duration of the key")
	invoke        = flag.Bool("invoke", false, "Specifies if the key has invoke permission")
	listen        = flag.Bool("listen", false, "Specifies if the key has listen permission")
	channelRegexp = flag.String("channel", ".*", "Specifies the channel regexp to apply the rule")
)

func main() {
	keyStore, err := token.LoadKeyStore(*tokenFile)
	if err != nil {
		keyStore = token.CreateKeyStore()
	}
	rule := token.ACLRule{}
	if *invoke {
		rule.InvokeControl = token.Allow
	}
	if *listen {
		rule.ListenControl = token.Allow
	}
	rule.ChannelRegexp = *channelRegexp
	log.Printf("New Token: %s", keyStore.GenerateKeyAndRegister(*keyName, []token.ACLRule{rule}, *duration))
	if err := keyStore.Save(*tokenFile); err != nil {
		log.Fatalf("failed to save the token file: %v", err)
	}
}
