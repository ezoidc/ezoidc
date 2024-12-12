package server

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"net/http/httptest"

	"github.com/ezoidc/ezoidc/pkg/models"
	"github.com/gin-gonic/gin"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/assert"
)

var rsaKey *rsa.PrivateKey
var jwks *jose.JSONWebKeySet

func init() {
	gin.SetMode(gin.TestMode)

	rsaKey, _ = rsa.GenerateKey(rand.Reader, 2048)
	jwks = generateJWKS()
}

func generateJWKS() *jose.JSONWebKeySet {
	return &jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{
				Key:   &rsaKey.PublicKey,
				KeyID: "someKeyID",
				Use:   "sig",
			},
		},
	}
}

func sign(claims map[string]interface{}) string {
	signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: rsaKey}, &jose.SignerOptions{
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			jose.HeaderKey("kid"): "someKeyID",
			jose.HeaderKey("typ"): "JWT",
		},
	})
	token, _ := jwt.Signed(signer).Claims(claims).Serialize()
	return token
}

func signWrongAlg() string {
	key := []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: key}, &jose.SignerOptions{})
	token, _ := jwt.Signed(signer).Claims(map[string]interface{}{
		"iss":   "http://127.0.0.1:3000",
		"aud":   "http://127.0.0.1:3000",
		"valid": true,
	}).Serialize()
	return token
}

func signWrongKid() string {
	signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: rsaKey}, &jose.SignerOptions{
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			jose.HeaderKey("kid"): "unknown",
			jose.HeaderKey("typ"): "JWT",
		},
	})
	token, _ := jwt.Signed(signer).Claims(map[string]interface{}{
		"iss":   "http://127.0.0.1:3000",
		"aud":   "http://127.0.0.1:3000",
		"valid": true,
	}).Serialize()
	return token
}

func TestValidToken(t *testing.T) {
	issuer := "http://127.0.0.1:3000"
	cfg := &models.Configuration{
		Audience: []string{issuer},
		Issuers: map[string]*models.Issuer{
			"mock": {
				Name:   "mock",
				Issuer: issuer,
				JWKS:   &models.JWKS{Keys: jwks.Keys},
			},
		},
		Algorithms: []jose.SignatureAlgorithm{"RS256"},
	}

	cases := []struct {
		token  string
		code   int
		err    string
		reason string
	}{
		{
			code: 200,
			token: sign(map[string]interface{}{
				"iss":   issuer,
				"aud":   issuer,
				"exp":   time.Now().Add(time.Minute).Unix(),
				"nbf":   time.Now().Add(-2 * time.Minute).Unix(),
				"valid": true,
			}),
		},
		{
			code: 401,
			token: sign(map[string]interface{}{
				"iss": issuer,
				"aud": "wrong-audience",
			}),
			err:    "go-jose/go-jose/jwt: validation failed, invalid audience claim (aud)",
			reason: "invalid:claims:aud",
		},
		{
			code: 401,
			token: sign(map[string]interface{}{
				"iss": "unsupported-issuer",
				"aud": cfg.Audience[0],
			}),
			err:    "invalid token issuer",
			reason: "invalid:claims:iss",
		},
		{
			code:   401,
			token:  "aaa",
			err:    "invalid token or algorithm",
			reason: "invalid:jwt",
		},
		{
			code:   401,
			token:  "e30K.e30K.aaaa",
			err:    "invalid token or algorithm",
			reason: "invalid:jwt",
		},
		{
			code: 401,
			token: sign(map[string]interface{}{
				"iss": issuer,
				"aud": issuer,
				"exp": time.Now().Add(-time.Minute).Unix(),
			}),
			err:    "go-jose/go-jose/jwt: validation failed, token is expired (exp)",
			reason: "invalid:claims:exp",
		},
		{
			code: 401,
			token: sign(map[string]interface{}{
				"iss": issuer,
				"aud": issuer,
				"nbf": time.Now().Add(2 * time.Minute).Unix(),
			}),
			err:    "go-jose/go-jose/jwt: validation failed, token not valid yet (nbf)",
			reason: "invalid:claims:nbf",
		},
		{
			code: 401,
			token: sign(map[string]interface{}{
				"iss": issuer,
				"aud": issuer,
				"iat": time.Now().Add(2 * time.Minute).Unix(),
			}),
			err:    "go-jose/go-jose/jwt: validation field, token issued in the future (iat)",
			reason: "invalid:claims:iat",
		},
		{
			code:   401,
			token:  signWrongAlg(),
			err:    "invalid token or algorithm",
			reason: "invalid:jwt",
		},
		{
			code:   401,
			token:  signWrongKid(),
			err:    "go-jose/go-jose: JWK with matching kid not found in JWK Set",
			reason: "invalid:kid",
		},
	}

	g := gin.Default()
	g.Use(BearerToken())
	g.Use(ValidToken(cfg))
	g.GET("/", func(c *gin.Context) {
		assert.Equal(t, c.GetString("issuer"), "mock")
		assert.Equal(t, c.GetStringMap("claims")["valid"], true)

		c.JSON(200, gin.H{"ezoidc": true})
	})

	for _, c := range cases {
		req, _ := http.NewRequest("GET", "/", nil)
		w := httptest.NewRecorder()
		req.Header.Set("Authorization", "Bearer "+c.token)
		g.ServeHTTP(w, req)
		assert.Equal(t, c.code, w.Code, c.token)
		var body struct {
			Error  string `json:"error"`
			Reason string `json:"reason"`
		}
		err := json.Unmarshal(w.Body.Bytes(), &body)
		assert.NoError(t, err)

		if c.err != "" {
			assert.Equal(t, c.err, body.Error)
			assert.Equal(t, c.reason, body.Reason)
		}
	}
}

func TestBearerToken(t *testing.T) {
	cases := map[string]struct {
		header string
		status int
		body   string
	}{
		"bearer": {
			header: "Bearer token",
			status: 200,
			body:   `"token"`,
		},
		"basic": {
			header: "Basic token",
			status: 401,
			body:   `{"error":"Authorization header scheme must be Bearer","reason":"invalid:jwt"}`,
		},
		"empty": {
			header: "",
			status: 401,
			body:   `{"error":"Authorization header is empty","reason":"invalid:jwt"}`,
		},
	}

	g := gin.Default()
	g.Use(BearerToken())
	g.GET("/", func(c *gin.Context) {
		c.JSON(200, c.GetString("bearer_token"))
	})

	for id, c := range cases {
		t.Run(id, func(t *testing.T) {
			req, _ := http.NewRequest("GET", "/", nil)
			w := httptest.NewRecorder()
			if c.header != "" {
				req.Header.Set("Authorization", c.header)
			}
			g.ServeHTTP(w, req)
			assert.Equal(t, c.status, w.Code, id)
			assert.Equal(t, c.body, w.Body.String(), id)
		})
	}
}
