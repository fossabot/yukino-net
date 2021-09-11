package cmd

import (
	"log"
	"time"

	"github.com/spf13/cobra"
)

var configFile string
var rpcTimeout time.Duration

var rootCmd = &cobra.Command{
	Use:   "yukino-net",
	Short: "yukino-net is a CLI to interative with microservices on Yukino network.",
}

var socksCmd = &cobra.Command{
	Use:   "socks5 [channel]",
	Short: "Create a socks5 proxy server on specified channel",
	Long:  "socks5 will create a proxy server to forward socks from `channel` to the network on local machine.",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		StartSocks5Proxy(configFile, args[0])
	},
}

var mountCmd = &cobra.Command{
	Use:   "mount [channel] [local address]",
	Short: "Mount `channel` to `local address`",
	Long:  "mount will listen on the specified address, and forward all traffic through this address to `channel`.",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		Mount(configFile, args[0], args[1])
	},
}

var httpFileCmd = &cobra.Command{
	Use:   "httpfile [channel] [directory]",
	Short: "Create a Http File server on `channel`",
	Long:  "httpfile will create a http file server on `channel` to serve file content on `directory`.",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		StartHTTPFileService(configFile, args[0], args[1])
	},
}

var endpointCmd = &cobra.Command{
	Use:   "endpoint [command]",
	Short: "Command set related to EndPoint RPC.",
}

var endpointServerCmd = &cobra.Command{
	Use:   "serve [channel]",
	Short: "Create an EndPoint RPC service on `channel`",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		err := StartEndPointService(cmd.Context(), configFile, args[0])
		if err != nil {
			log.Printf("Service returns status: %v", err)
		}
	},
}

var endpointCallCmd = &cobra.Command{
	Use:   "call [channel] [command]",
	Short: "Invoke an EndPoint RPC service on `channel`",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		result, err := InvokeEndPointShellProxyService(cmd.Context(), configFile, args[0], args[1], rpcTimeout)
		if err != nil {
			log.Printf("Error: %v", err)
			return
		}
		if len(result) > 0 {
			log.Printf("Result: %s", result)
		} else {
			log.Printf("Service returns without result.")
		}
	},
}

var routerCmd = &cobra.Command{
	Use:   "route",
	Short: "Create a Yukino network described in the config file.",
	Long:  "Route command will create a new Network that all other services can rely on.",
	Run: func(cmd *cobra.Command, args []string) {
		err := StartRouter(configFile)
		if err != nil {
			log.Printf("Error: %v", err)
			return
		}
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		log.Fatalf("failed to execute Root command: %v", err)
	}
}

func init() {
	endpointCallCmd.Flags().DurationVarP(&rpcTimeout, "timeout", "t", 3*time.Second, "The timeout to invoke the RPC service.")
	endpointCmd.AddCommand(endpointServerCmd)
	endpointCmd.AddCommand(endpointCallCmd)

	rootCmd.PersistentFlags().StringVarP(&configFile, "config", "c", "config.json", "Configuration file to join the router network.")
	rootCmd.AddCommand(socksCmd)
	rootCmd.AddCommand(mountCmd)
	rootCmd.AddCommand(httpFileCmd)
	rootCmd.AddCommand(endpointCmd)
	rootCmd.AddCommand(routerCmd)
}
