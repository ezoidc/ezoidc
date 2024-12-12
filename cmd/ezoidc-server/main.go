// ezoidc server
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/ezoidc/ezoidc/pkg/engine"
	"github.com/ezoidc/ezoidc/pkg/models"
	"github.com/ezoidc/ezoidc/pkg/server"
	"github.com/ezoidc/ezoidc/pkg/static"
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var configPath string

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version and build information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("github.com/ezoidc/ezoidc@%s (%s)\n", static.Version, static.Commit)
	},
}

var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the server",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		config, err := models.ReadConfiguration(configPath)
		if err != nil {
			return err
		}

		level, _ := zerolog.ParseLevel(config.LogLevel)
		log.Logger = log.Logger.Level(level)

		err = config.PreloadJWKS(ctx)
		if err != nil {
			return err
		}

		eng := engine.NewEngine(config)
		err = eng.Compile(ctx)
		if err != nil {
			return err
		}

		gin.SetMode(gin.ReleaseMode)
		return server.NewAPI(eng).Run()
	},
}

var testClaims string
var testParams string
var testVariablesCmd = &cobra.Command{
	Use:   "variables",
	Short: "Allowed variables given the provided claims",
	RunE: func(cmd *cobra.Command, args []string) error {
		var res engine.ReadResponse
		var claims map[string]any
		var params map[string]any
		err := json.Unmarshal([]byte(testClaims), &claims)
		if err != nil {
			return err
		}
		err = json.Unmarshal([]byte(testParams), &params)
		if err != nil {
			return err
		}

		ctx := cmd.Context()
		config, err := models.ReadConfiguration(configPath)
		if err != nil {
			return err
		}

		eng := engine.NewEngine(config)
		err = eng.Compile(ctx)
		if err != nil {
			return err
		}

		allowed, err := eng.AllowedVariables(ctx, &engine.ReadRequest{
			Claims: claims,
			Params: params,
		})
		if err != nil {
			return err
		}
		res.Allowed = allowed

		return models.JSONEncoder(os.Stdout).Encode(res)
	},
}

func main() {
	log.Logger = zerolog.New(os.Stdout).With().Timestamp().Logger()

	rootCmd := &cobra.Command{
		Use:           "ezoidc",
		Long:          `ezoidc server`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(startCmd)

	testCmd := &cobra.Command{
		Use:   "test",
		Short: "Test the server configuration",
	}
	rootCmd.AddCommand(testCmd)
	testCmd.AddCommand(testVariablesCmd)

	testVariablesCmd.Flags().StringVar(&testClaims, "claims", "{}", "Claims to use for the test")
	testVariablesCmd.Flags().StringVar(&testParams, "params", "{}", "Params to use for the test")

	rootCmd.PersistentFlags().StringVarP(&configPath,
		"config", "c", "config.yaml",
		"Path to the configuration file",
	)

	if len(os.Args) == 1 {
		rootCmd.SetArgs([]string{"start"})
	}

	if err := rootCmd.ExecuteContext(context.Background()); err != nil {
		log.Error().Err(err).Send()
		os.Exit(1)
	}
}
