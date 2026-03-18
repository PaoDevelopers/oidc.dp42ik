package main

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Claims struct {
	Email string `json:"email"`
	jwt.RegisteredClaims
}

type tokenValidationError struct {
	PublicMessage string
}

func (e *tokenValidationError) Error() string {
	return e.PublicMessage
}

type jwksDocument struct {
	Keys []jwkKey `json:"keys"`
}

type jwkKey struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type jwkCache struct {
	mu   sync.RWMutex
	keys map[string]*rsa.PublicKey
}

var (
	providerHTTPClient = &http.Client{Timeout: 10 * time.Second}
	providerKeys       jwkCache
)

func buildAuthorizationURL(serviceID string) string {
	v := url.Values{}
	v.Set("client_id", oidcClientID)
	v.Set("redirect_uri", oidcRedirectURL)
	v.Set("response_type", "id_token")
	v.Set("response_mode", "form_post")
	v.Set("scope", "openid email")
	v.Set("prompt", "login")
	v.Set("svc", serviceID)

	return oidcAuthEndpoint + "?" + v.Encode()
}

func verifyIDToken(ctx context.Context, raw string) (*Claims, error) {
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg(), jwt.SigningMethodRS384.Alg(), jwt.SigningMethodRS512.Alg()}),
		jwt.WithIssuer(oidcIssuer),
		jwt.WithAudience(oidcClientID),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithLeeway(30*time.Second),
	)

	claims := &Claims{}
	token, err := parser.ParseWithClaims(raw, claims, keyFunc(ctx))
	if err != nil {
		return nil, classifyJWTError(err)
	}
	if !token.Valid {
		return nil, &tokenValidationError{PublicMessage: "Invalid JWT"}
	}

	claims.Email = strings.ToLower(strings.TrimSpace(claims.Email))
	if claims.Email == "" {
		return nil, &tokenValidationError{PublicMessage: "JWT missing email claim"}
	}

	return claims, nil
}

func keyFunc(ctx context.Context) jwt.Keyfunc {
	return func(token *jwt.Token) (any, error) {
		kid, _ := token.Header["kid"].(string)
		if kid == "" {
			return nil, fmt.Errorf("missing kid")
		}

		if key := providerKeys.get(kid); key != nil {
			return key, nil
		}
		if err := refreshJWKS(ctx); err != nil {
			return nil, err
		}
		if key := providerKeys.get(kid); key != nil {
			return key, nil
		}
		return nil, fmt.Errorf("unknown kid %q", kid)
	}
}

func refreshJWKS(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, oidcJWKSURL, nil)
	if err != nil {
		return err
	}

	resp, err := providerHTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("jwks fetch failed with status %s", resp.Status)
	}

	var doc jwksDocument
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return err
	}

	keys := make(map[string]*rsa.PublicKey, len(doc.Keys))
	for _, jwk := range doc.Keys {
		if jwk.Kty != "RSA" || jwk.Kid == "" {
			continue
		}
		pub, err := rsaKeyFromJWK(jwk)
		if err != nil {
			slog.Warn("ignoring invalid jwk", slog.String("kid", jwk.Kid), slog.Any("error", err))
			continue
		}
		keys[jwk.Kid] = pub
	}
	if len(keys) == 0 {
		return errors.New("jwks contained no usable rsa keys")
	}

	providerKeys.set(keys)
	return nil
}

func rsaKeyFromJWK(jwk jwkKey) (*rsa.PublicKey, error) {
	nb, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, err
	}
	eb, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return nil, err
	}

	e := 0
	for _, b := range eb {
		e = e<<8 | int(b)
	}
	if e <= 0 {
		return nil, errors.New("invalid rsa exponent")
	}

	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(nb),
		E: e,
	}, nil
}

func classifyJWTError(err error) error {
	switch {
	case errors.Is(err, jwt.ErrTokenMalformed):
		return &tokenValidationError{PublicMessage: "Malformed JWT"}
	case errors.Is(err, jwt.ErrTokenSignatureInvalid):
		return &tokenValidationError{PublicMessage: "Invalid JWT signature"}
	case errors.Is(err, jwt.ErrTokenExpired):
		return &tokenValidationError{PublicMessage: "JWT expired"}
	case errors.Is(err, jwt.ErrTokenNotValidYet):
		return &tokenValidationError{PublicMessage: "JWT not valid yet"}
	case errors.Is(err, jwt.ErrTokenInvalidIssuer):
		return &tokenValidationError{PublicMessage: "Invalid JWT issuer"}
	case errors.Is(err, jwt.ErrTokenInvalidAudience):
		return &tokenValidationError{PublicMessage: "Invalid JWT audience"}
	case errors.Is(err, jwt.ErrTokenUnverifiable):
		return &tokenValidationError{PublicMessage: "Unverifiable JWT"}
	default:
		return err
	}
}

func (c *jwkCache) get(kid string) *rsa.PublicKey {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.keys[kid]
}

func (c *jwkCache) set(keys map[string]*rsa.PublicKey) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.keys = keys
}
