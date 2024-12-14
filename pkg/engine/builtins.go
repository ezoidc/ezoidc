package engine

import (
	"time"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/topdown"
	"github.com/open-policy-agent/opa/topdown/builtins"
	"github.com/open-policy-agent/opa/types"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

func init() {
	rego.RegisterBuiltin1(&rego.Function{
		Name: "totp_verify",
		Decl: types.NewFunction(types.Args(types.NewObject(
			[]*types.StaticProperty{
				types.NewStaticProperty("secret", types.S),
				types.NewStaticProperty("code", types.S),
			},
			nil,
		)), types.B),
	}, builtinTotpVerify)
}

func builtinTotpVerify(bctx topdown.BuiltinContext, op *ast.Term) (*ast.Term, error) {
	obj, err := builtins.ObjectOperand(op.Value, 1)
	if err != nil {
		return nil, err
	}
	var code string
	var secret string
	var t time.Time = time.Now()

	obj.Foreach(func(key *ast.Term, value *ast.Term) {
		switch k := key.Value.(type) {
		case ast.String:
			switch string(k) {
			case "code":
				switch c := value.Value.(type) {
				case ast.String:
					code = string(c)
				case ast.Number:
					code = c.String()
				}
			case "secret":
				secret = string(value.Value.(ast.String))
			case "time":
				switch c := value.Value.(type) {
				case ast.Number:
					v, _ := c.Int64()
					t = time.Unix(0, v)
				}
			}
		}
	})

	if code == "" || secret == "" {
		return nil, builtins.NewOperandErr(1, "code and secret must be provided")
	}

	valid, err := totp.ValidateCustom(code, secret, t, totp.ValidateOpts{
		Period:    30,
		Skew:      1,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		return nil, err
	}

	return ast.BooleanTerm(valid), nil
}
