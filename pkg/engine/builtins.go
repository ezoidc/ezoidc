package engine

import (
	"fmt"
	"time"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/topdown"
	"github.com/open-policy-agent/opa/v1/topdown/builtins"
	"github.com/open-policy-agent/opa/v1/types"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/rs/zerolog/log"
)

func init() {
	rego.RegisterBuiltin1(totpVerify, func(bctx rego.BuiltinContext, op *ast.Term) (*ast.Term, error) {
		ret, err := builtinTotpVerify(bctx, op)
		if err != nil {
			log.Warn().
				Str("location", bctx.Location.String()).
				Msgf("%s: %v", totpVerify.Name, err)
			return nil, err
		}
		return ret, nil
	})
}

var totpVerify = &rego.Function{
	Name: "totp_verify",
	Decl: types.NewFunction(types.Args(types.NewObject(
		[]*types.StaticProperty{
			types.NewStaticProperty("secret", types.S),
			types.NewStaticProperty("code", types.S),
		},
		types.NewDynamicProperty(types.S, types.N),
	)), types.B),
}

func builtinTotpVerify(_ topdown.BuiltinContext, op *ast.Term) (*ast.Term, error) {
	obj, err := builtins.ObjectOperand(op.Value, 1)
	if err != nil {
		return nil, err
	}

	var code string
	var secret string
	var skew uint = 1
	var period uint
	var t time.Time = time.Now()

	err = obj.Iter(func(keyTerm *ast.Term, valueTerm *ast.Term) error {
		key, err := builtins.StringOperand(keyTerm.Value, 1)
		if err != nil {
			return err
		}

		switch key {
		case "code":
			code, err = argString(key, valueTerm)
			if err != nil {
				return err
			}
		case "secret":
			secret, err = argString(key, valueTerm)
			if err != nil {
				return err
			}
		case "time":
			v, err := argNumber(key, valueTerm)
			if err != nil {
				return err
			}
			t = time.Unix(0, v)
		case "skew":
			v, err := argNumber(key, valueTerm)
			if err != nil {
				return err
			}
			skew = uint(v)
		case "period":
			v, err := argNumber(key, valueTerm)
			if err != nil {
				return err
			}
			period = uint(v)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	if code == "" || secret == "" {
		return nil, builtins.NewOperandErr(1, "argument `code` and `secret` must not be empty")
	}

	valid, err := totp.ValidateCustom(code, secret, t, totp.ValidateOpts{
		Skew:      skew,
		Period:    period,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		return nil, err
	}

	return ast.BooleanTerm(valid), nil
}

func argError(key string, got *ast.Term, expected string) error {
	return fmt.Errorf("argument `%s` must be a %s, got %s", key, expected, ast.TypeName(got.Value))
}

func argString(key ast.String, value *ast.Term) (string, error) {
	v, err := builtins.StringOperand(value.Value, 1)
	if err != nil {
		return "", argError(string(key), value, "string")
	}
	return string(v), nil
}

func argNumber(key ast.String, value *ast.Term) (int64, error) {
	v, err := builtins.NumberOperand(value.Value, 1)
	if err != nil {
		return 0, argError(string(key), value, "number")
	}
	n, _ := v.Int64()
	return n, nil
}
