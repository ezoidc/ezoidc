// ezoidc server
package main

import (
	"context"
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

		engine := engine.NewEngine(config)
		err = engine.Compile(ctx)
		if err != nil {
			return err
		}

		gin.SetMode(gin.ReleaseMode)
		return server.NewAPI(engine).Run()
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

	startCmd.Flags().StringVarP(&configPath,
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
