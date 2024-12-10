// ezoidc cli
package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"

	"al.essio.dev/pkg/shellescape"
	"github.com/ezoidc/ezoidc/pkg/client"
	"github.com/ezoidc/ezoidc/pkg/models"
	"github.com/ezoidc/ezoidc/pkg/static"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

type State struct {
	host       string
	token      string
	tokenPath  string
	paramsList *[]string
	params     map[string]any
}

var state State

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version and build information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("github.com/ezoidc/ezoidc@%s (%s)\n", static.Version, static.Commit)
	},
}

var variablesCmd = &cobra.Command{
	Use:   "variables",
	Short: "Read variables",
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		return state.prepare()
	},
}

var variablesJsonCmd = &cobra.Command{
	Use:   "json",
	Short: "Read variables in JSON format",
	RunE: func(cmd *cobra.Command, args []string) error {
		variablesResponse, err := client.NewAPIClient(http.DefaultClient, state.host).
			GetVariables(context.Background(), &models.VariablesRequest{
				Token:  state.token,
				Params: state.params,
			})
		if err != nil {
			return err
		}

		return models.JSONEncoder(os.Stdout).Encode(variablesResponse)
	},
}

var variablesEnvCmd = &cobra.Command{
	Use:   "env",
	Short: "Read variables in ENV format",
	RunE: func(cmd *cobra.Command, args []string) error {
		variablesResponse, err := client.NewAPIClient(http.DefaultClient, state.host).
			GetVariables(context.Background(), &models.VariablesRequest{
				Token:  state.token,
				Params: state.params,
			})
		if err != nil {
			return err
		}
		for _, value := range variablesResponse.Variables {
			if value.Export == "" {
				continue
			}

			fmt.Printf("# %s\n", shellescape.Quote(value.Name))
			fmt.Printf(
				"export %s=%s\n\n",
				shellescape.Quote(value.Export),
				shellescape.Quote(value.Value.String),
			)
		}
		return nil
	},
}

var variablesExecCmd = &cobra.Command{
	Use:   "exec",
	Short: "Execute a command with environment variables set",
	RunE: func(cmd *cobra.Command, args []string) error {
		variablesResponse, err := client.NewAPIClient(http.DefaultClient, state.host).
			GetVariables(context.Background(), &models.VariablesRequest{
				Token:  state.token,
				Params: state.params,
			})
		if err != nil {
			return err
		}

		exe := exec.Command(args[0], args[1:]...)
		exe.Stderr = os.Stderr
		exe.Stdout = os.Stdout
		exe.Stdin = os.Stdin
		exe.Env = os.Environ()
		exe.Dir = cmd.Flag("cwd").Value.String()

		// remove EZOIDC_TOKEN from env
		for i, env := range exe.Env {
			if strings.HasPrefix(env, "EZOIDC_TOKEN=") {
				exe.Env = append(exe.Env[:i], exe.Env[i+1:]...)
				break
			}
		}

		for _, value := range variablesResponse.Variables {
			if value.Export == "" {
				continue
			}

			log.Debug().Msgf("setting env %s (%s)", value.Export, value.Name)
			exe.Env = append(exe.Env, fmt.Sprintf("%s=%s", value.Export, value.Value.String))
		}

		return exe.Run()
	},
}

func main() {
	log.Logger = zerolog.New(os.Stderr).With().Timestamp().Logger().Level(zerolog.InfoLevel)
	rootCmd := &cobra.Command{
		Use:          "ezoidc",
		Long:         `ezoidc cli`,
		SilenceUsage: true,
	}
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(variablesCmd)
	variablesCmd.AddCommand(variablesJsonCmd)
	variablesCmd.AddCommand(variablesEnvCmd)
	variablesCmd.AddCommand(variablesExecCmd)

	variablesExecCmd.Flags().String("cwd", "", "Execute the command in the given directory")

	variablesCmd.PersistentFlags().StringVarP(&state.tokenPath,
		"token-path", "t", os.Getenv("EZOIDC_TOKEN_PATH"),
		"Path to a file containing a token (env: EZOIDC_TOKEN_PATH)")

	variablesCmd.PersistentFlags().StringVar(&state.host,
		"host", os.Getenv("EZOIDC_HOST"),
		"Override the host address of the server (env: EZOIDC_HOST)")

	state.paramsList = variablesCmd.PersistentFlags().
		StringArrayP("param", "p", nil, "Parameter name=value to include in the request")

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

var allAlgorithms = []jose.SignatureAlgorithm{
	jose.RS256, jose.RS384, jose.RS512,
	jose.ES256, jose.ES384, jose.ES512,
	jose.PS256, jose.PS384, jose.PS512,
}

func audience(token string) (string, error) {
	j, err := jwt.ParseSigned(token, allAlgorithms)
	if err != nil {
		return "", err
	}

	var claims jwt.Claims
	err = j.UnsafeClaimsWithoutVerification(&claims)
	if err != nil {
		return "", err
	}

	if len(claims.Audience) == 0 {
		return "", fmt.Errorf("no audience")
	}

	return claims.Audience[0], nil
}

func (s *State) prepare() error {
	if s.tokenPath != "" {
		token, err := os.ReadFile(s.tokenPath)
		if err != nil {
			return fmt.Errorf("failed to read token file: %w", err)
		}
		s.token = strings.TrimSpace(string(token))
	}

	if s.token == "" {
		s.token = os.Getenv("EZOIDC_TOKEN")
	}

	if s.token == "" {
		return fmt.Errorf("missing token")
	}

	if state.host == "" {
		host, _ := audience(state.token)
		state.host = host
	}

	state.params = map[string]any{}
	for _, param := range *s.paramsList {
		parts := strings.SplitN(param, "=", 2)
		if len(parts) != 2 {
			return fmt.Errorf("invalid param: %s", param)
		}
		state.params[parts[0]] = parts[1]
	}

	return nil
}
