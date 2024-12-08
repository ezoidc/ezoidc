package engine

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/ezoidc/ezoidc/pkg/models"
	"github.com/ezoidc/ezoidc/pkg/providers"
	"github.com/ezoidc/ezoidc/pkg/static"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage/inmem"
	"github.com/open-policy-agent/opa/topdown/print"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

const (
	QueryAllowedVariables  = "allowed_variables"
	QueryVariablesResponse = "variables_response"
)

type Engine struct {
	// Variable resolver
	Resolver *providers.Resolver
	// List of defined variable names
	Definitions []string
	// Compiled Rego query
	Query rego.PreparedEvalQuery
	// Engine configuration
	Configuration *models.Configuration
}

type EngineInput struct {
	// Which query from data.ezoidc._queries to evaluate
	Query string `json:"query"`
	// Variables given to the policy
	Variables []models.Variable `json:"variables"`
	// Validated JWT claims
	Claims map[string]any `json:"claims"`
	// Variable names and their allowed scope (read or internal)
	Allow map[string]string `json:"allow"`
}

type ReadResponse struct {
	Variables []models.Variable `json:"variables,omitempty"`
	Allowed   map[string]string `json:"allowed"`
}

// Create a new policy engine using default variable resolvers
func NewEngine(config *models.Configuration) *Engine {
	return &Engine{
		Resolver:      providers.NewResolver().WithDefaultProviders(),
		Configuration: config,
	}
}

//go:embed ezoidc.rego
var ezoidcRego string

// Prepare the engine for evaluation
func (e *Engine) Compile(ctx context.Context) error {
	c, err := ast.CompileModulesWithOpt(map[string]string{
		"ezoidc.rego": ezoidcRego,
		"policy.rego": "package ezoidc\n" + e.Configuration.Policy,
	}, ast.CompileOpts{
		EnablePrintStatements: true,
		ParserOptions: ast.ParserOptions{
			RegoVersion: ast.RegoV1,
		}},
	)
	if err != nil {
		return err
	}

	defs := map[string]bool{}
	for _, r := range c.Modules["policy.rego"].Rules {
		ref := r.Head.Ref()
		if ref[0].Value.String() == "define" {
			if !ast.IsScalar(ref[1].Value) {
				return fmt.Errorf("%s: defined variable names must be a scalar", ref[1].Location.String())
			}
			v := ref[1].Value.(ast.String)
			defs[string(v)] = true
		}
	}
	e.Definitions = []string{}
	for def := range defs {
		e.Definitions = append(e.Definitions, def)
	}

	variableNames := e.Definitions
	for _, v := range e.Configuration.Variables {
		variableNames = append(variableNames, v.Name)
	}

	store := inmem.NewFromObject(map[string]interface{}{
		"issuers":        e.Configuration.Issuers,
		"variable_names": variableNames,
		"version":        static.Version,
	})
	query, err := rego.New(
		rego.Query("data.ezoidc._queries[input.query]"),
		rego.Compiler(c),
		rego.Store(store),
	).PrepareForEval(ctx)
	if err != nil {
		return err
	}

	e.Query = query
	return nil
}

// Given validated claims, determine allowed variables name and scope
func (e *Engine) Allowed(ctx context.Context, claims map[string]any) (map[string]string, error) {
	allowed := map[string]string{}
	input := &EngineInput{
		Query:  QueryAllowedVariables,
		Claims: claims,
	}
	err := e.eval(ctx, input, &allowed)
	if err != nil {
		return nil, err
	}
	return allowed, nil
}

// Given validated claims, read allowed variable values
func (e *Engine) Read(ctx context.Context, claims map[string]any) (*ReadResponse, error) {
	allowed, err := e.Allowed(ctx, claims)
	if err != nil {
		return nil, err
	}

	allowedVariables := []models.Variable{}
	for _, v := range e.Configuration.Variables {
		if allowed[v.Name] != "" {
			allowedVariables = append(allowedVariables, v)
		}
	}

	resolvedVariables, err := e.Resolver.Resolve(ctx, allowedVariables)
	if err != nil {
		return nil, err
	}

	response := &ReadResponse{Allowed: allowed}
	input := &EngineInput{
		Query:     QueryVariablesResponse,
		Variables: resolvedVariables,
		Claims:    claims,
		Allow:     allowed,
	}
	err = e.eval(ctx, input, &response.Variables)
	if err != nil {
		return nil, err
	}

	return response, nil
}

// Handle print calls from Rego
func (e *Engine) Print(ctx print.Context, msg string) error {
	var line *zerolog.Event
	before, after, found := strings.Cut(msg, ": ")
	if found {
		level, err := zerolog.ParseLevel(before)
		if err != nil || level == zerolog.NoLevel {
			level = zerolog.DebugLevel
		} else {
			msg = after
		}
		line = log.WithLevel(level)
	} else {
		line = log.Debug()
	}

	line.Any("request_id", ctx.Context.Value("request_id")).
		Str("location", ctx.Location.String()).
		Msg(msg)
	return nil
}

func (e *Engine) eval(ctx context.Context, input *EngineInput, out interface{}) error {
	rs, err := e.Query.Eval(ctx,
		rego.EvalInput(input),
		rego.EvalPrintHook(e),
	)
	if err != nil {
		return err
	}
	if len(rs) == 0 {
		return fmt.Errorf("no result set")
	}

	data, err := json.Marshal(rs[0].Expressions[0].Value)
	if err != nil {
		return err
	}

	return json.Unmarshal(data, out)
}
