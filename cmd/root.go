/*
Copyright © 2020 Derrick Martinez <derrick.martinez@gmail.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"fmt"
	"os"
	"strings"
	"github.com/derrickmartinez/wireguard-auth/pkg/mfa"
	"github.com/derrickmartinez/wireguard-auth/pkg/user"
	"github.com/derrickmartinez/wireguard-auth/pkg/util"

    "github.com/aws/aws-sdk-go/aws"
    "github.com/aws/aws-sdk-go/aws/session"
    "github.com/aws/aws-sdk-go/service/dynamodb"
	homedir "github.com/mitchellh/go-homedir"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/spf13/cobra"

)

var cfgFile string
var cfgVars util.CmdVars

var logLevels = map[string]log.Level{
        "panic": log.PanicLevel,
        "fatal": log.FatalLevel,
        "error": log.ErrorLevel,
        "warn":  log.WarnLevel,
        "info":  log.InfoLevel,
        "debug": log.DebugLevel,
        "trace": log.TraceLevel,
}

var rootCmd = &cobra.Command{
	Use:   "wireguard-auth [sub]",
	Short: "Wireguard Auth",
	Run: func(cmd *cobra.Command, args []string) {
	    cmd.Help()
	    os.Exit(1)
	},
}

var authCmd = &cobra.Command{
	Use:   "auth",
	Short: "Authenticate a user using 2FA",
	Run: func(cmd *cobra.Command, args []string) {
	  	if !mfa.Validate(&cfgVars, awsSession()) {
	  		os.Exit(1)
	  	}
	},
}

var addUserCmd = &cobra.Command{
	Use:   "add",
	Short: "Add a user to the database",
	Run: func(cmd *cobra.Command, args []string) {
		user.Add(&cfgVars, awsSession())
	},
}

var removeUserCmd = &cobra.Command{
	Use:   "remove",
	Short: "Remove a user from the database",
	Run: func(cmd *cobra.Command, args []string) {
		user.Remove(&cfgVars, awsSession())
	},
}

var syncCmd = &cobra.Command{
	Use:   "sync",
	Short: "Sync wireguard with dynamodb (runs in foreground)",
	Run: func(cmd *cobra.Command, args []string) {
                user.Sync(&cfgVars, awsSession())
	},
}

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List all users",
	Run: func(cmd *cobra.Command, args []string) {
                user.List(awsSession())
	},
}

var rotateUserCmd = &cobra.Command{
	Use:   "rotate",
	Short: "Rotate a user's public key",
	Run: func(cmd *cobra.Command, args []string) {
		user.Rotate(&cfgVars, awsSession())
	},
}

func awsSession() *dynamodb.DynamoDB {
	// Set up AWS session
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String(viper.GetString("region")),
	})
	if err != nil {
		log.Fatal("Error creating AWS Session: %v\n", err)
		os.Exit(1)
	}
	// Create DynamoDB client
	return dynamodb.New(sess)
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.wireguard-auth.yaml)")

	addUserCmd.Flags().StringVar(&cfgVars.ProfileName, "profile-name", "", "Profile name to add to database")
	addUserCmd.Flags().BoolVar(&cfgVars.SplitTunnel, "split-tunnel", false, "Use split tunnel (default false)")
	addUserCmd.Flags().StringVar(&cfgVars.RoutesAllow, "routes-allow", "", "Allow CIDRs (if different from default). Example: 1.1.1.1/32,2.0.0.0/8")
	addUserCmd.Flags().StringVar(&cfgVars.Email, "email", "", "Email")
	addUserCmd.MarkFlagRequired("profile-name")
	addUserCmd.MarkFlagRequired("email")
	rootCmd.AddCommand(addUserCmd)

	removeUserCmd.Flags().StringVar(&cfgVars.ProfileName, "profile-name", "", "Profile name to remove from database")
	removeUserCmd.MarkFlagRequired("profile-name")
	rootCmd.AddCommand(removeUserCmd)

	authCmd.Flags().StringVar(&cfgVars.PubKey, "pubkey", "", "Pubkey of the vpn user to authenticate")
	authCmd.MarkFlagRequired("pubkey")
	rootCmd.AddCommand(authCmd)
	rootCmd.AddCommand(syncCmd)
	rootCmd.AddCommand(listCmd)

	rotateUserCmd.Flags().StringVar(&cfgVars.ProfileName, "profile-name", "", "Profile name to rotate keys for")
	rotateUserCmd.Flags().StringVar(&cfgVars.PubKey, "pubkey", "", "Pubkey of the vpn user to authenticate")
	rotateUserCmd.MarkFlagRequired("profile-name")
	rotateUserCmd.MarkFlagRequired("pubkey")
	rootCmd.AddCommand(rotateUserCmd)
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := homedir.Dir()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
        viper.AutomaticEnv() // read in environment variables that match
        viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

		// Search config in home directory with name ".wireguard-auth" (without extension).
		viper.AddConfigPath(home)
		viper.SetConfigName(".wireguard-auth")
	}

    // If a config file is found, read it in.
    if err := viper.ReadInConfig(); err == nil {
            if l, exists := logLevels[strings.ToLower(viper.GetString("logLevel"))]; exists {
                    log.SetLevel(l)
            }
            log.Traceln("Log level set to", log.GetLevel().String())
            log.WithField("file", viper.ConfigFileUsed()).Debugln("Using config file")
    }
}
