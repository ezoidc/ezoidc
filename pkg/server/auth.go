package server

import (
	"strings"
	"time"

	"github.com/ezoidc/ezoidc/pkg/models"
	"github.com/gin-gonic/gin"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

const (
	ReasonInvalidJwt    = "invalid:jwt"
	ReasonInvalidKid    = "invalid:kid"
	ReasonInvalidClaims = "invalid:claims"
)

func BearerToken() gin.HandlerFunc {
	return func(c *gin.Context) {
		authorization := c.GetHeader("Authorization")
		if authorization == "" {
			authError(c, "Authorization header is empty", ReasonInvalidJwt)
			return
		}

		scheme, token, _ := strings.Cut(authorization, " ")
		if scheme != "Bearer" {
			authError(c, "Authorization header scheme must be Bearer", ReasonInvalidJwt)
			return
		}

		c.Set("bearer_token", token)
	}
}

func ValidToken(config *models.Configuration) gin.HandlerFunc {
	return func(c *gin.Context) {
		bearerToken := c.GetString("bearer_token")
		token, err := jwt.ParseSigned(bearerToken, config.Algorithms)
		if err != nil {
			authError(c, "invalid token or algorithm", ReasonInvalidJwt)
			return
		}

		var claims jwt.Claims
		_ = token.UnsafeClaimsWithoutVerification(&claims)

		issuer := config.GetIssuer(claims.Issuer)
		if issuer == nil {
			c.Set("issuer", claims.Issuer)
			authError(c, "invalid token issuer", reasonFromError(jwt.ErrInvalidIssuer))
			return
		}
		c.Set("issuer", issuer.Name)

		// verify token signature
		var validatedClaims map[string]interface{}
		err = token.Claims(jose.JSONWebKeySet(*issuer.JWKS), &validatedClaims)
		if err != nil {
			authError(c, err.Error(), ReasonInvalidKid)
			return
		}

		// verify token claims
		err = claims.ValidateWithLeeway(jwt.Expected{
			Issuer:      issuer.Issuer,
			AnyAudience: jwt.Audience(config.Audience),
			Time:        time.Now(),
		}, time.Minute)
		if err != nil {
			authError(c, err.Error(), reasonFromError(err))
			return
		}

		c.Set("claims", validatedClaims)
	}
}

func authError(ctx *gin.Context, err string, reason string) {
	ctx.Set("reason", reason)
	ctx.AbortWithStatusJSON(401, gin.H{
		"error":  err,
		"reason": reason,
	})
}

func reasonFromError(err error) string {
	reason := ReasonInvalidClaims
	switch err {
	case jwt.ErrInvalidAudience:
		reason += ":aud"
	case jwt.ErrInvalidIssuer:
		reason += ":iss"
	case jwt.ErrExpired:
		reason += ":exp"
	case jwt.ErrNotValidYet:
		reason += ":nbf"
	case jwt.ErrIssuedInTheFuture:
		reason += ":iat"
	}
	return reason
}
