package builtins

import (
	"context"

	"github.com/ezoidc/ezoidc/pkg/providers"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/topdown"
	"github.com/open-policy-agent/opa/v1/topdown/builtins"
	"github.com/open-policy-agent/opa/v1/types"
	authv1 "k8s.io/api/authentication/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
)

var kubernetesServiceAccountToken = &rego.Function{
	Name: "kubernetes_service_account_token",
	Decl: types.NewFunction(
		types.Args(types.NewObject(
			[]*types.StaticProperty{
				types.NewStaticProperty("service_account", types.S),
			},
			types.NewDynamicProperty(types.S, types.A),
		)),
		types.S,
	),
}

type kubernetesServiceAccountTokenClient interface {
	CreateToken(ctx context.Context, namespace string, serviceAccount string, tokenRequest *authv1.TokenRequest) (string, error)
}

type inClusterKubernetesServiceAccountTokenClient struct {
	client kubernetes.Interface
}

func (c *inClusterKubernetesServiceAccountTokenClient) CreateToken(
	ctx context.Context,
	namespace string,
	serviceAccount string,
	tokenRequest *authv1.TokenRequest,
) (string, error) {
	resp, err := c.client.CoreV1().
		ServiceAccounts(namespace).
		CreateToken(ctx, serviceAccount, tokenRequest, v1.CreateOptions{})
	if err != nil {
		return "", err
	}
	return resp.Status.Token, nil
}

func newKubernetesServiceAccountTokenClient() (kubernetesServiceAccountTokenClient, error) {
	client, err := providers.CurrentKubernetesClient()
	if err != nil {
		return nil, err
	}

	return &inClusterKubernetesServiceAccountTokenClient{client: client}, nil
}

func builtinKubernetesServiceAccountToken(bctx topdown.BuiltinContext, op *ast.Term) (*ast.Term, error) {
	obj, err := builtins.ObjectOperand(op.Value, 1)
	if err != nil {
		return nil, err
	}

	var (
		serviceAccount    string
		namespace         string
		audiences         []string
		boundObjectKind   string
		boundObjectName   string
		boundObjectUID    string
		expirationSeconds int64
	)

	err = obj.Iter(func(keyTerm *ast.Term, valueTerm *ast.Term) error {
		key, err := builtins.StringOperand(keyTerm.Value, 1)
		if err != nil {
			return err
		}

		switch key {
		case "service_account":
			serviceAccount, err = argString(key, valueTerm)
			if err != nil {
				return err
			}
		case "namespace":
			namespace, err = argString(key, valueTerm)
			if err != nil {
				return err
			}
		case "audiences":
			audiences, err = argStringArray(key, valueTerm)
			if err != nil {
				return err
			}
		case "expiration_seconds":
			expirationSeconds, err = argNumber(key, valueTerm)
			if err != nil {
				return err
			}
		case "bound_object_kind":
			boundObjectKind, err = argString(key, valueTerm)
			if err != nil {
				return err
			}
		case "bound_object_name":
			boundObjectName, err = argString(key, valueTerm)
			if err != nil {
				return err
			}
		case "bound_object_uid":
			boundObjectUID, err = argString(key, valueTerm)
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	if serviceAccount == "" {
		return nil, builtins.NewOperandErr(1, "argument `service_account` must not be empty")
	}

	if namespace == "" {
		namespace = providers.CurrentKubernetesNamespace()
	}

	if expirationSeconds < 0 {
		return nil, builtins.NewOperandErr(1, "argument `expiration_seconds` must be greater than or equal to 0")
	}

	hasBoundObject := boundObjectKind != "" || boundObjectName != "" || boundObjectUID != ""
	tokenRequest := &authv1.TokenRequest{}

	if len(audiences) > 0 || expirationSeconds > 0 || hasBoundObject {
		tokenRequest.Spec = authv1.TokenRequestSpec{
			Audiences: audiences,
		}

		if expirationSeconds > 0 {
			tokenRequest.Spec.ExpirationSeconds = &expirationSeconds
		}

		if hasBoundObject {
			tokenRequest.Spec.BoundObjectRef = &authv1.BoundObjectReference{
				Kind: boundObjectKind,
				Name: boundObjectName,
				UID:  k8stypes.UID(boundObjectUID),
			}
		}
	}

	client, err := newKubernetesServiceAccountTokenClient()
	if err != nil {
		return nil, err
	}

	token, err := client.CreateToken(bctx.Context, namespace, serviceAccount, tokenRequest)
	if err != nil {
		return nil, err
	}

	return ast.StringTerm(token), nil
}
