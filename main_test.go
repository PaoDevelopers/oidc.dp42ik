package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/chacha20poly1305"
)

func TestUserIDFromEmail(t *testing.T) {
	allowedEmailDomain = "stu.ykpaoschool.cn"

	got, err := userIDFromEmail("S12345@stu.ykpaoschool.cn")
	if err != nil {
		t.Fatalf("userIDFromEmail returned error: %v", err)
	}
	if got != "s12345" {
		t.Fatalf("userIDFromEmail = %q, want %q", got, "s12345")
	}
}

func TestMarshalTicket(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	buf, _, err := marshalTicket("cca", "s12345", now, 60*time.Second, "OIDC")
	if err != nil {
		t.Fatalf("marshalTicket returned error: %v", err)
	}
	issuedAt, err := unixSeconds(now)
	if err != nil {
		t.Fatalf("unixSeconds(now) returned error: %v", err)
	}
	expiresAt, err := unixSeconds(now.Add(60 * time.Second))
	if err != nil {
		t.Fatalf("unixSeconds(now.Add(...)) returned error: %v", err)
	}
	if len(buf) != ticketSize {
		t.Fatalf("ticket size = %d, want %d", len(buf), ticketSize)
	}
	if got := binary.BigEndian.Uint64(buf[137:145]); got != issuedAt {
		t.Fatalf("issued_at = %d, want %d", got, issuedAt)
	}
	if got := binary.BigEndian.Uint64(buf[145:153]); got != expiresAt {
		t.Fatalf("expires_at = %d, want %d", got, expiresAt)
	}
}

func TestIssueTicket(t *testing.T) {
	svc := ServiceConfig{
		ID:          "cca",
		KeyID:       7,
		Key:         bytes.Repeat([]byte{0x42}, 32),
		DisplayName: "CCA",
		TTL:         60 * time.Second,
	}

	wire, _, err := issueTicket(svc, "s12345", "OIDC")
	if err != nil {
		t.Fatalf("issueTicket returned error: %v", err)
	}

	if got := wire[0]; got != svc.KeyID {
		t.Fatalf("wire key id = %d, want %d", got, svc.KeyID)
	}

	aead, err := chacha20poly1305.NewX(svc.Key)
	if err != nil {
		t.Fatalf("NewX returned error: %v", err)
	}
	nonce := wire[1 : 1+chacha20poly1305.NonceSizeX]
	plain, err := aead.Open(nil, nonce, wire[1+chacha20poly1305.NonceSizeX:], []byte("web1cca"))
	if err != nil {
		t.Fatalf("Open returned error: %v", err)
	}
	if len(plain) != ticketSize {
		t.Fatalf("plaintext size = %d, want %d", len(plain), ticketSize)
	}
}

func TestVerifyIDToken(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey returned error: %v", err)
	}

	oidcIssuer = "https://issuer.example"
	oidcClientID = "portal-client"
	oidcJWKSURL = "http://jwks.example.local/keys"
	providerKeys.set(map[string]*rsa.PublicKey{
		"kid1": &key.PublicKey,
	})

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, Claims{
		Email: "S12345@stu.ykpaoschool.cn",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    oidcIssuer,
			Subject:   "subject-1",
			Audience:  []string{oidcClientID},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-time.Minute)),
		},
	})
	token.Header["kid"] = "kid1"

	raw, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("SignedString returned error: %v", err)
	}

	claims, err := verifyIDToken(context.Background(), raw)
	if err != nil {
		t.Fatalf("verifyIDToken returned error: %v", err)
	}
	if claims.Email != "s12345@stu.ykpaoschool.cn" {
		t.Fatalf("claims.Email = %q", claims.Email)
	}
}

func TestHandleAuth(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey returned error: %v", err)
	}

	allowedEmailDomain = "stu.ykpaoschool.cn"
	oidcIssuer = "https://issuer.example"
	oidcClientID = "portal-client"
	service = ServiceConfig{
		ID:          "cca",
		Origin:      "https://service.example",
		ConsumePath: "/dp42ik",
		KeyID:       1,
		Key:         bytes.Repeat([]byte{0x11}, 32),
		DisplayName: "CCA Selection Service",
		TTL:         60 * time.Second,
	}
	providerKeys.set(map[string]*rsa.PublicKey{
		"kid1": &key.PublicKey,
	})

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, Claims{
		Email: "S12345@stu.ykpaoschool.cn",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    oidcIssuer,
			Subject:   "subject-1",
			Audience:  []string{oidcClientID},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-time.Minute)),
		},
	})
	token.Header["kid"] = "kid1"

	raw, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("SignedString returned error: %v", err)
	}

	form := url.Values{}
	form.Set("id_token", raw)
	req := httptest.NewRequest(http.MethodPost, "/auth", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	handleAuth(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "Continue to CCA Selection Service") {
		t.Fatalf("unexpected body: %s", rec.Body.String())
	}
}

func TestRefreshJWKS(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey returned error: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jwksDocument{
			Keys: []jwkKey{{
				Kid: "kid1",
				Kty: "RSA",
				N:   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
				E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
			}},
		})
	}))
	defer srv.Close()

	oidcJWKSURL = srv.URL
	providerHTTPClient = srv.Client()

	if err := refreshJWKS(context.Background()); err != nil {
		t.Fatalf("refreshJWKS returned error: %v", err)
	}
	if providerKeys.get("kid1") == nil {
		t.Fatal("kid1 not loaded")
	}
}
