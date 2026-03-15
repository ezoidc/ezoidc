package builtins

import (
	"crypto/rand"
	"encoding/binary"
	"time"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/topdown"
	"github.com/open-policy-agent/opa/v1/topdown/builtins"
	"github.com/open-policy-agent/opa/v1/types"
	"golang.org/x/crypto/ssh"
)

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
