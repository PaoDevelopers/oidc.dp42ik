package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"
)

var (
	listenAddr         string
	oidcIssuer         string
	oidcClientID       string
	oidcAuthEndpoint   string
	oidcJWKSURL        string
	oidcRedirectURL    string
	allowedEmailDomain string

	serviceID          string
	serviceOrigin      string
	serviceConsumePath string
	serviceKeyID       int
	serviceKeyRaw      string
	serviceDisplayName string
	serviceTTL         time.Duration
	service            ServiceConfig
)

func parseFlags() {
	flag.StringVar(&listenAddr, "listen", "", "TCP listen address")
	flag.StringVar(&oidcIssuer, "oidc-issuer", "", "OIDC issuer URL")
	flag.StringVar(&oidcClientID, "oidc-client-id", "", "OIDC client ID")
	flag.StringVar(&oidcAuthEndpoint, "oidc-auth-endpoint", "", "OIDC authorization endpoint URL")
	flag.StringVar(&oidcJWKSURL, "oidc-jwks-url", "", "OIDC JWKS URL")
	flag.StringVar(&oidcRedirectURL, "oidc-redirect-url", "", "OIDC redirect URL for this portal")
	flag.StringVar(&allowedEmailDomain, "allowed-email-domain", "", "allowed email domain")

	flag.StringVar(&serviceID, "service-id", "", "service identifier")
	flag.StringVar(&serviceOrigin, "service-origin", "", "service origin URL")
	flag.StringVar(&serviceConsumePath, "service-consume-path", "", "service consume path")
	flag.IntVar(&serviceKeyID, "service-key-id", -1, "service key identifier")
	flag.StringVar(&serviceKeyRaw, "service-key-b64", "", "service ticket key in base64") // TODO: could be seen in process list
	flag.StringVar(&serviceDisplayName, "service-display-name", "", "service display name")
	flag.DurationVar(&serviceTTL, "service-ttl", 0, "service ticket lifetime, e.g. 60s")

	flag.Parse()

	mustFlag("listen", listenAddr)
	mustFlag("oidc-issuer", oidcIssuer)
	mustFlag("oidc-client-id", oidcClientID)
	mustFlag("oidc-auth-endpoint", oidcAuthEndpoint)
	mustFlag("oidc-jwks-url", oidcJWKSURL)
	mustFlag("oidc-redirect-url", oidcRedirectURL)
	mustFlag("allowed-email-domain", allowedEmailDomain)
	mustFlag("service-id", serviceID)
	mustFlag("service-origin", serviceOrigin)
	mustFlag("service-consume-path", serviceConsumePath)
	mustFlag("service-key-b64", serviceKeyRaw)
	mustFlag("service-display-name", serviceDisplayName)
	if serviceKeyID < 0 || serviceKeyID > 255 {
		exitUsage("service-key-id must be between 0 and 255")
	}
	if serviceTTL <= 0 {
		exitUsage("service-ttl must be positive")
	}

	mustURL("oidc-issuer", oidcIssuer)
	mustURL("oidc-auth-endpoint", oidcAuthEndpoint)
	mustURL("oidc-jwks-url", oidcJWKSURL)
	mustURL("oidc-redirect-url", oidcRedirectURL)
	mustURL("service-origin", serviceOrigin)
	if !strings.HasPrefix(serviceConsumePath, "/") {
		exitUsage("service-consume-path must start with '/'")
	}

	key, err := base64.StdEncoding.DecodeString(serviceKeyRaw)
	if err != nil {
		exitUsage(fmt.Sprintf("service-key-b64 must be valid base64: %v", err))
	}
	if len(key) != 32 {
		exitUsage("service-key-b64 must decode to exactly 32 bytes")
	}

	service = ServiceConfig{
		ID:          serviceID,
		Origin:      strings.TrimRight(serviceOrigin, "/"),
		ConsumePath: serviceConsumePath,
		KeyID:       byte(serviceKeyID),
		Key:         key,
		DisplayName: serviceDisplayName,
		TTL:         serviceTTL,
	}
}

func mustFlag(name, value string) {
	if strings.TrimSpace(value) == "" {
		exitUsage("missing required flag -" + name)
	}
}

func mustURL(name, raw string) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		exitUsage(fmt.Sprintf("%s must be an absolute URL", name))
	}
}

func exitUsage(msg string) {
	fmt.Fprintln(os.Stderr, msg)
	flag.Usage()
	os.Exit(2)
}
