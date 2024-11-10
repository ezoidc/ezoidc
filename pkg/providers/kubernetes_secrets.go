package providers

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/rs/zerolog/log"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

type KubernetesSecretsClient interface {
	GetSecret(ctx context.Context, namespace string, name string) (map[string][]byte, error)
}

type KubernetesSecretsProvider struct {
	Client    KubernetesSecretsClient
	Namespace string
}

type KubernetesClient struct {
	Client *kubernetes.Clientset
}

func (c *KubernetesClient) GetSecret(ctx context.Context, namespace string, name string) (map[string][]byte, error) {
	secret, err := c.Client.CoreV1().Secrets(namespace).Get(ctx, name, v1.GetOptions{})
	if err != nil {
		return nil, err
	}
	return secret.Data, nil
}

func NewKubernetesProvider() *KubernetesSecretsProvider {
	return &KubernetesSecretsProvider{}
}

func (p *KubernetesSecretsProvider) Read(ctx context.Context, variables map[string]string) (map[string]string, error) {
	if err := p.configure(); err != nil {
		return nil, err
	}

	result := map[string]string{}
	secretGroups := map[string]map[string]map[string][]string{}
	for variable, id := range variables {
		namespace, secret, property, err := p.parseKubernetesID(id)
		if err != nil {
			return nil, err
		}

		if secretGroups[namespace] == nil {
			secretGroups[namespace] = map[string]map[string][]string{}
		}

		if secretGroups[namespace][secret] == nil {
			secretGroups[namespace][secret] = map[string][]string{}
		}

		secretGroups[namespace][secret][property] = append(secretGroups[namespace][secret][property], variable)
	}

	for namespace, secrets := range secretGroups {
		for secret, properties := range secrets {
			data, err := p.Client.GetSecret(ctx, namespace, secret)
			log.Debug().
				Err(err).
				Str("namespace", namespace).
				Str("secret", secret).
				Msg("get kubernetes secret")

			if err != nil {
				log.Warn().Err(err).
					Str("namespace", namespace).
					Str("secret", secret).
					Msg("could not get kubernetes secret")
				continue
			}

			for property, variables := range properties {
				for _, variable := range variables {
					val, ok := data[property]
					result[variable] = string(val)

					if !ok {
						log.Warn().
							Str("namespace", namespace).Str("secret", secret).
							Str("property", property).Str("variable", variable).
							Msg("property not found in kubernetes secret")
					}
				}
			}
		}
	}

	return result, nil
}

func (p *KubernetesSecretsProvider) parseKubernetesID(id string) (namespace string, secret string, property string, err error) {
	parts := strings.Split(id, "/")
	if len(parts) == 3 {
		namespace = parts[0]
		secret = parts[1]
		property = parts[2]
	} else if len(parts) == 2 {
		secret = parts[0]
		property = parts[1]
		namespace = p.Namespace
	} else {
		err = fmt.Errorf("invalid kubernetes secret id: %s", id)
	}
	return
}

func (p *KubernetesSecretsProvider) configure() error {
	if p.Client != nil {
		return nil
	}

	config, err := rest.InClusterConfig()
	if err != nil {
		return err
	}

	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return err
	}

	p.Client = &KubernetesClient{Client: client}
	p.Namespace = os.Getenv("KUBERNETES_POD_NAMESPACE")
	if p.Namespace == "" {
		ns, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
		if err == nil {
			p.Namespace = string(ns)
		} else {
			log.Debug().Msg("failed to obtain current kubernetes namespace, using default")
			p.Namespace = "default"
		}
	}

	return nil
}
