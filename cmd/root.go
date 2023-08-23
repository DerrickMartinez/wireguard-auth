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
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	homedir "github.com/mitchellh/go-homedir"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var cfgFile string
var cfgVars util.CmdVars

var logLevels = map[string]zerolog.Level{
	"panic": zerolog.PanicLevel,
	"fatal": zerolog.FatalLevel,
	"error": zerolog.ErrorLevel,
	"warn":  zerolog.WarnLevel,
	"info":  zerolog.InfoLevel,
	"debug": zerolog.DebugLevel,
	"trace": zerolog.TraceLevel,
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
		if len(cfgVars.Routes) == 0 && len(cfgVars.Rule) == 0 {
			fmt.Println("Error: You must specify a rule or routes")
			os.Exit(1)
		}
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

var updateRoutesCmd = &cobra.Command{
	Use:   "update-routes",
	Short: "Change a user's routes",
	Run: func(cmd *cobra.Command, args []string) {
		if len(cfgVars.Routes) == 0 && len(cfgVars.Rule) == 0 {
			fmt.Println("Error: You must specify a rule or routes")
			os.Exit(1)
		}
		user.UpdateRoutes(&cfgVars, awsSession())
	},
}

var resendEmailCmd = &cobra.Command{
	Use:   "resend-email",
	Short: "Email config to user again",
	Run: func(cmd *cobra.Command, args []string) {
		user.ResendEmail(&cfgVars, awsSession())
	},
}

func awsSession() *dynamodb.DynamoDB {
	// Set up AWS session
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String(viper.GetString("region")),
	})
	if err != nil {
		log.Fatal().Err(err).Msg("Error creating AWS Session")
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

	addUserCmd.Flags().StringVar(&cfgVars.ProfileName, "profile", "", "Profile name")
	addUserCmd.Flags().BoolVar(&cfgVars.SplitTunnel, "split-tunnel", false, "Use split tunnel (default false)")
	addUserCmd.Flags().StringVar(&cfgVars.Rule, "rule", "", "Use a routing rule (optional)")
	addUserCmd.Flags().StringVar(&cfgVars.Routes, "routes", "", "Allow routes separated by comma with or without port/proto i.e. 1.1.1.1/32->22/tcp,2.0.0.0/8 (optional)")
	addUserCmd.Flags().StringVar(&cfgVars.Email, "email", "", "Email")
	addUserCmd.MarkFlagRequired("profile")
	addUserCmd.MarkFlagRequired("email")
	rootCmd.AddCommand(addUserCmd)

	removeUserCmd.Flags().StringVar(&cfgVars.ProfileName, "profile", "", "Profile name")
	removeUserCmd.MarkFlagRequired("profile")
	rootCmd.AddCommand(removeUserCmd)

	authCmd.Flags().StringVar(&cfgVars.PubKey, "pubkey", "", "Pubkey of the vpn user")
	authCmd.Flags().StringVar(&cfgVars.Endpoint, "endpoint", "", "Endpoint of the user authenticating")
	authCmd.MarkFlagRequired("pubkey")
	rootCmd.AddCommand(authCmd)
	rootCmd.AddCommand(syncCmd)
	rootCmd.AddCommand(listCmd)

	updateRoutesCmd.Flags().StringVar(&cfgVars.ProfileName, "profile", "", "Profile name")
	updateRoutesCmd.Flags().StringVar(&cfgVars.Rule, "rule", "", "Use a routing rule (optional)")
	updateRoutesCmd.Flags().StringVar(&cfgVars.Routes, "routes", "", "Allow routes separated by comma with or without port/proto i.e. 1.1.1.1/32->22/tcp,2.0.0.0/8 (optional)")
	updateRoutesCmd.MarkFlagRequired("profile")
	rootCmd.AddCommand(updateRoutesCmd)

	resendEmailCmd.Flags().StringVar(&cfgVars.ProfileName, "profile", "", "Profile name")
	resendEmailCmd.MarkFlagRequired("profile")
	rootCmd.AddCommand(resendEmailCmd)
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
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
			zerolog.SetGlobalLevel(l)
			log.Info().Msgf("Log level set to %v\n", l)
		}

		log.Debug().Str("file", viper.ConfigFileUsed()).Msg("Using config file")
	}
}
