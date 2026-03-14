package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"dagger/e-2-e/internal/dagger"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"

	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/ssh"
)

func (m *E2E) TestSSHCert(ctx context.Context) error {
	issuer := NewIssuer()
	caKeyPEM, clientPrivateKeyPEM, publicKey := generateSSHCertE2EKeys()

	config := Configuration{
		Audience: "http://ezoidc:3501",
		Listen:   "0.0.0.0:3501",
		Policy: `
			allow.read("cert") if {
				issuer = "dagger"
			  subject = "alice"
			}

			allow.internal("private_ca_key")

			define.cert.value = ssh_certificate({
			  "ca_key": read("private_ca_key"),
			  "public_key": params.public_key,
			  "principals": ["sudo"],
			  "critical_options": {
			    "force-command": "echo CERT_OK",
			  },
			})
		`,
		Variables: map[string]any{
			"private_ca_key": map[string]any{
				"value": map[string]any{
					"string": caKeyPEM,
				},
			},
		},
		Issuers: map[string]any{
			"dagger": map[string]any{
				"issuer": "http://localhost:3000",
				"jwks":   issuer.MarshalJWKS(),
			},
		},
	}

	server := dag.Container().
		From(baseImage).
		WithMountedFile("/bin/ezoidc-server", m.EzoidcServer).
		WithNewFile("/config.yaml", config.MarshalYAML()).
		WithExposedPort(3501).
		AsService(dagger.ContainerAsServiceOpts{
			Args: []string{"/bin/ezoidc-server", "start", "/config.yaml"},
		})

	output, err := dag.Container().
		From(baseImage).
		WithServiceBinding("ezoidc", server).
		WithMountedFile("/bin/ezoidc", m.Ezoidc).
		WithEnvVariable("EZOIDC_TOKEN", issuer.SignToken(map[string]any{
			"iss": "http://localhost:3000",
			"aud": []string{"http://ezoidc:3501"},
			"sub": "alice",
		})).
		WithExec([]string{
			"/bin/ezoidc", "variables", "json", "--param", fmt.Sprintf("public_key=%s", publicKey),
		}).
		Stdout(ctx)
	assert.NoError(t, err)

	variables := &Variables{}
	_ = json.Unmarshal([]byte(output), variables)

	certRaw, ok := variables.Values()["cert"]
	if !assert.True(t, ok, "expected cert variable to be present") {
		return nil
	}

	caSigner, err := ssh.ParsePrivateKey([]byte(caKeyPEM))
	assert.NoError(t, err)

	sshdConfig := strings.TrimSpace(`
Port 22
Protocol 2
HostKey /etc/ssh/ssh_host_ed25519_key
HostKey /etc/ssh/ssh_host_rsa_key
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
UsePAM no
PermitRootLogin no
TrustedUserCAKeys /etc/ssh/trusted-user-ca-keys.pub
AuthorizedPrincipalsFile /etc/ssh/auth_principals/%u
PidFile /run/sshd.pid
LogLevel VERBOSE
`)

	sshServer := dag.Container().
		From(baseImage).
		WithExec([]string{"apk", "add", "--no-cache", "openssh-server"}).
		WithExec([]string{"sh", "-lc", `
			adduser -D alice
			echo alice:alice | chpasswd
			mkdir -p /run/sshd /etc/ssh/auth_principals
			echo sudo > /etc/ssh/auth_principals/alice
			chmod 644 /etc/ssh/auth_principals/alice
			ssh-keygen -A
		`}).
		WithNewFile("/etc/ssh/trusted-user-ca-keys.pub", string(ssh.MarshalAuthorizedKey(caSigner.PublicKey()))).
		WithNewFile("/etc/ssh/sshd_config", sshdConfig+"\n").
		WithExposedPort(22).
		AsService(dagger.ContainerAsServiceOpts{
			Args: []string{"/usr/sbin/sshd", "-D", "-e", "-f", "/etc/ssh/sshd_config"},
		})

	sshOutput, err := dag.Container().
		From(baseImage).
		WithExec([]string{"apk", "add", "--no-cache", "openssh-client"}).
		WithServiceBinding("openssh", sshServer).
		WithNewFile("/home/alice/.ssh/id_rsa", clientPrivateKeyPEM, dagger.ContainerWithNewFileOpts{Permissions: 0o600}).
		WithNewFile("/home/alice/.ssh/id_rsa-cert.pub", certRaw, dagger.ContainerWithNewFileOpts{Permissions: 0o644}).
		WithExec([]string{"sh", "-lc", `
			ssh \
				-o StrictHostKeyChecking=no \
				-o UserKnownHostsFile=/dev/null \
				-o IdentitiesOnly=yes \
				-o ConnectTimeout=2 \
				-o CertificateFile=/home/alice/.ssh/id_rsa-cert.pub \
				-o IdentityFile=/home/alice/.ssh/id_rsa \
				alice@openssh
		`}).
		Stdout(ctx)
	assert.NoError(t, err)
	assert.Equal(t, "CERT_OK\n", sshOutput, "cert force-command did not run")

	return nil
}

func generateSSHCertE2EKeys() (string, string, string) {
	_, caPrivateKey, _ := ed25519.GenerateKey(rand.Reader)
	caPrivateBytes, _ := x509.MarshalPKCS8PrivateKey(caPrivateKey)
	caPrivatePEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: caPrivateBytes,
	})

	clientPrivateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	clientPrivateBytes := x509.MarshalPKCS1PrivateKey(clientPrivateKey)
	clientPrivatePEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: clientPrivateBytes,
	})

	sshClientPublicKey, _ := ssh.NewPublicKey(&clientPrivateKey.PublicKey)

	return string(caPrivatePEM), string(clientPrivatePEM), string(ssh.MarshalAuthorizedKey(sshClientPublicKey))
}
