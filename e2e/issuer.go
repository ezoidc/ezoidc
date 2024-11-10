package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

type Issuer struct {
	PrivateKey *rsa.PrivateKey
	JWKS       *jose.JSONWebKeySet
}

func NewIssuer() *Issuer {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	return &Issuer{
		PrivateKey: rsaKey,
		JWKS: &jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{
				{
					Key:   &rsaKey.PublicKey,
					KeyID: "someKeyID",
					Use:   "sig",
				},
			},
		},
	}
}

func (i *Issuer) SignToken(claims map[string]interface{}) string {
	signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: i.PrivateKey}, &jose.SignerOptions{
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			jose.HeaderKey("kid"): "someKeyID",
			jose.HeaderKey("typ"): "JWT",
		},
	})
	token, _ := jwt.Signed(signer).Claims(claims).Serialize()
	return token
}

func (i *Issuer) MarshalJWKS() string {
	s, _ := json.Marshal(i.JWKS)
	return string(s)
}
