package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/ezoidc/ezoidc/pkg/models"
	"github.com/go-jose/go-jose/v4"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

var (
	kubernetesPodNamespaceEnv = "KUBERNETES_POD_NAMESPACE"
	kubernetesServiceHostEnv  = "KUBERNETES_SERVICE_HOST"
	kubernetesNamespacePath   = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
	kubernetesNamespaceOnce   sync.Once
	kubernetesNamespace       string
	kubernetesClientOnce      sync.Once
	kubernetesClient          *kubernetes.Clientset
	kubernetesClientErr       error
)

func CurrentKubernetesNamespace() string {
	kubernetesNamespaceOnce.Do(func() {
		namespace := strings.TrimSpace(os.Getenv(kubernetesPodNamespaceEnv))
		if namespace != "" {
			kubernetesNamespace = namespace
			return
		}

		ns, err := os.ReadFile(kubernetesNamespacePath)
		if err == nil {
			namespace = strings.TrimSpace(string(ns))
			if namespace != "" {
				kubernetesNamespace = namespace
				return
			}
		}

		kubernetesNamespace = "default"
	})

	return kubernetesNamespace
}

func CurrentKubernetesClient() (*kubernetes.Clientset, error) {
	kubernetesClientOnce.Do(func() {
		config, err := rest.InClusterConfig()
		if err != nil {
			kubernetesClientErr = err
			return
		}

		kubernetesClient, kubernetesClientErr = kubernetes.NewForConfig(config)
	})

	return kubernetesClient, kubernetesClientErr
}

func ConfigureKubernetesIssuer(ctx context.Context, config *models.Configuration) error {
	if config == nil || config.Issuers["k8s"] != nil {
		return nil
	}

	issuer, err := DetectKubernetesIssuer(ctx)
	if err != nil {
		return err
	}
	if issuer != nil {
		config.Issuers["k8s"] = issuer
	}

	return nil
}

func DetectKubernetesIssuer(ctx context.Context) (*models.Issuer, error) {
	if os.Getenv(kubernetesServiceHostEnv) == "" {
		return nil, nil
	}

	client, err := CurrentKubernetesClient()
	if err == rest.ErrNotInCluster {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	req := client.RESTClient().Get().AbsPath("/.well-known/openid-configuration")
	resp, err := req.DoRaw(ctx)
	if err != nil {
		return nil, err
	}

	var oidcConfig struct {
		Issuer  string `json:"issuer"`
		JwksURI string `json:"jwks_uri"`
	}
	if err := json.Unmarshal(resp, &oidcConfig); err != nil {
		return nil, err
	}

	req = client.RESTClient().Get().AbsPath("/openid/v1/jwks")
	resp, err = req.DoRaw(ctx)
	if err != nil {
		return nil, err
	}

	var jwks jose.JSONWebKeySet
	if err := json.Unmarshal(resp, &jwks); err != nil {
		return nil, fmt.Errorf("failed to unmarshal k8s jwks: %w", err)
	}

	modelJWKS := models.JWKS(jwks)
	return &models.Issuer{
		Name:    "k8s",
		Issuer:  oidcConfig.Issuer,
		JWKSURI: oidcConfig.JwksURI,
		JWKS:    &modelJWKS,
	}, nil
}
