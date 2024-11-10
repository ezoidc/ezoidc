package models

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLoadJwksDiscovery(t *testing.T) {
	var testServer *httptest.Server
	paths := []string{}
	testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		paths = append(paths, req.URL.Path)
		switch req.URL.Path {
		case "/.well-known/openid-configuration":
			j, _ := json.Marshal(map[string]string{
				"jwks_uri": testServer.URL + "/jwks",
			})
			_, _ = res.Write(j)
		case "/jwks":
			_, _ = res.Write([]byte(`{"keys":[{"use":"sig","kty":"RSA","kid":"kid","alg":"RS256","n":"AAAA","e":"AQAB"}]}`))
		default:
			t.Fatalf("unexpected request: %s", req.URL.Path)
		}
	}))
	iss := &Issuer{Issuer: testServer.URL}
	err := iss.LoadJWKS(context.TODO(), testServer.Client())
	assert.NoError(t, err)
	assert.Equal(t, []string{"/.well-known/openid-configuration", "/jwks"}, paths)
}

func TestLoadJwksNoDiscovery(t *testing.T) {
	testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/jwks":
			_, _ = res.Write([]byte(`{"keys":[{"use":"sig","kty":"RSA","kid":"kid","alg":"RS256","n":"AAAA","e":"AQAB"}]}`))
		default:
			t.Fatalf("unexpected request: %s", req.URL.Path)
		}
	}))
	iss := &Issuer{Issuer: testServer.URL, JWKSURI: testServer.URL + "/jwks"}
	err := iss.LoadJWKS(context.TODO(), testServer.Client())
	assert.NoError(t, err)
}

func TestLoadJwksStatic(t *testing.T) {
	testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		t.Fatalf("unexpected request: %s", req.URL.Path)
	}))
	iss := &Issuer{Issuer: testServer.URL, JWKS: &JWKS{}}
	err := iss.LoadJWKS(context.TODO(), testServer.Client())
	assert.NoError(t, err)
}
