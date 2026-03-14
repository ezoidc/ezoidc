package engine

import (
	"crypto/rand"
	"encoding/binary"
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
	"golang.org/x/crypto/ssh"
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

var sshCert = &rego.Function{
	Name: "ssh_certificate",
	Decl: types.NewFunction(
		types.Args(types.NewObject(
			[]*types.StaticProperty{
				types.NewStaticProperty("ca_key", types.S),
				types.NewStaticProperty("public_key", types.S),
			},
			types.NewDynamicProperty(types.S, types.A),
		)),
		types.S,
	),
}

func builtinTotpVerify(_ topdown.BuiltinContext, op *ast.Term) (*ast.Term, error) {
	obj, err := builtins.ObjectOperand(op.Value, 1)
	if err != nil {
		return nil, err
	}

	var code string
	var secret string
	var skew uint
	var period uint
	var t = time.Now()

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

func builtinSSHCert(_ topdown.BuiltinContext, op *ast.Term) (*ast.Term, error) {
	obj, err := builtins.ObjectOperand(op.Value, 1)
	if err != nil {
		return nil, err
	}

	var caKeyRaw string
	var publicKeyRaw string
	var certType uint32 = ssh.UserCert
	keyID := ""
	principals := []string{}
	validAfter := uint64(time.Now().Unix())
	ttl := 22 * time.Hour
	criticalOptions := map[string]string{}
	extensions := map[string]string{}

	err = obj.Iter(func(keyTerm *ast.Term, valueTerm *ast.Term) error {
		key, err := builtins.StringOperand(keyTerm.Value, 1)
		if err != nil {
			return err
		}

		switch key {
		case "ca_key":
			caKeyRaw, err = argString(key, valueTerm)
			if err != nil {
				return err
			}
		case "public_key":
			publicKeyRaw, err = argString(key, valueTerm)
			if err != nil {
				return err
			}
		case "cert_type":
			v, err := argString(key, valueTerm)
			if err != nil {
				return err
			}
			switch v {
			case "user":
				certType = ssh.UserCert
			case "host":
				certType = ssh.HostCert
			default:
				return builtins.NewOperandErr(1, "argument `cert_type` must be `user` or `host`")
			}
		case "key_id":
			keyID, err = argString(key, valueTerm)
			if err != nil {
				return err
			}
		case "principals":
			principals, err = argStringArray(key, valueTerm)
			if err != nil {
				return err
			}
		case "valid_after":
			v, err := argString(key, valueTerm)
			if err != nil {
				return err
			}
			if v == "now" {
				validAfter = uint64(time.Now().Unix())
				break
			}
			t, err := time.Parse(time.RFC3339, v)
			if err != nil {
				return builtins.NewOperandErr(1, "argument `valid_after` must be `now` or an RFC3339 timestamp")
			}
			if t.Unix() < 0 {
				return builtins.NewOperandErr(1, "argument `valid_after` must be after 1970-01-01T00:00:00Z")
			}
			validAfter = uint64(t.Unix())
		case "ttl":
			v, err := argString(key, valueTerm)
			if err != nil {
				return err
			}
			ttl, err = time.ParseDuration(v)
			if err != nil {
				return builtins.NewOperandErr(1, "argument `ttl` must be a valid duration")
			}
			if ttl <= 0 {
				return builtins.NewOperandErr(1, "argument `ttl` must be greater than 0")
			}
		case "critical_options":
			criticalOptions, err = argStringMap(key, valueTerm)
			if err != nil {
				return err
			}
		case "extensions":
			extensions, err = argStringMap(key, valueTerm)
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	if caKeyRaw == "" || publicKeyRaw == "" {
		return nil, builtins.NewOperandErr(1, "argument `ca_key` and `public_key` must not be empty")
	}

	caSigner, err := ssh.ParsePrivateKey([]byte(caKeyRaw))
	if err != nil {
		return nil, builtins.NewOperandErr(1, "invalid `ca_key`: %v", err)
	}

	publicKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(publicKeyRaw))
	if err != nil {
		return nil, builtins.NewOperandErr(1, "invalid `public_key`: %v", err)
	}

	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	serialBytes := make([]byte, 8)
	if _, err := rand.Read(serialBytes); err != nil {
		return nil, err
	}

	validBefore := validAfter + uint64(ttl.Seconds())
	cert := &ssh.Certificate{
		Nonce:           nonce,
		Key:             publicKey,
		Serial:          binary.BigEndian.Uint64(serialBytes),
		CertType:        certType,
		KeyId:           keyID,
		ValidPrincipals: principals,
		ValidAfter:      validAfter,
		ValidBefore:     validBefore,
		Permissions: ssh.Permissions{
			CriticalOptions: criticalOptions,
			Extensions:      extensions,
		},
	}

	if err := cert.SignCert(rand.Reader, caSigner); err != nil {
		return nil, err
	}

	return ast.StringTerm(string(ssh.MarshalAuthorizedKey(cert))), nil
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
