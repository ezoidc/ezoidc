package builtins

import (
	"fmt"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/topdown/builtins"
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

	rego.RegisterBuiltin1(sshCert, func(bctx rego.BuiltinContext, op *ast.Term) (*ast.Term, error) {
		ret, err := builtinSSHCert(bctx, op)
		if err != nil {
			log.Warn().
				Str("location", bctx.Location.String()).
				Msgf("%s: %v", sshCert.Name, err)
			return nil, err
		}
		return ret, nil
	})
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

func argStringArray(key ast.String, value *ast.Term) ([]string, error) {
	v, err := builtins.ArrayOperand(value.Value, 1)
	if err != nil {
		return nil, argError(string(key), value, "array")
	}
	out := make([]string, 0)
	err = v.Iter(func(elem *ast.Term) error {
		s, err := builtins.StringOperand(elem.Value, 1)
		if err != nil {
			return fmt.Errorf("argument `%s` must be an array of strings", key)
		}
		out = append(out, string(s))
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func argStringMap(key ast.String, value *ast.Term) (map[string]string, error) {
	v, err := builtins.ObjectOperand(value.Value, 1)
	if err != nil {
		return nil, argError(string(key), value, "object")
	}
	out := map[string]string{}
	err = v.Iter(func(keyTerm *ast.Term, valueTerm *ast.Term) error {
		k, err := builtins.StringOperand(keyTerm.Value, 1)
		if err != nil {
			return fmt.Errorf("argument `%s` must be an object with string keys", key)
		}
		val, err := builtins.StringOperand(valueTerm.Value, 1)
		if err != nil {
			return fmt.Errorf("argument `%s` must be an object with string values", key)
		}
		out[string(k)] = string(val)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
