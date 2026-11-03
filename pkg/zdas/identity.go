package zdas

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

// identityFile is the parsed content of a Ziti identity JSON file.
type identityFile struct {
	ZtAPI string `json:"ztAPI"`
	ID    struct {
		Cert string `json:"cert"`
		Key  string `json:"key"`
		CA   string `json:"ca"`
	} `json:"id"`
}

// parsedIdentity holds the decoded credentials from a Ziti identity file.
type parsedIdentity struct {
	APIURL  string
	TLSCert tls.Certificate
	CAPool  *x509.CertPool
}

// loadIdentityFile reads and parses a Ziti identity JSON file. The PEM fields
// may have an optional "pem:" prefix which is stripped.
func loadIdentityFile(path string) (*parsedIdentity, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read identity file: %w", err)
	}

	var idFile identityFile
	if err := json.Unmarshal(data, &idFile); err != nil {
		return nil, fmt.Errorf("parse identity file: %w", err)
	}

	certPEM := strings.TrimPrefix(idFile.ID.Cert, "pem:")
	keyPEM := strings.TrimPrefix(idFile.ID.Key, "pem:")
	caPEM := strings.TrimPrefix(idFile.ID.CA, "pem:")

	if certPEM == "" || keyPEM == "" {
		return nil, errors.New("identity file missing cert or key")
	}

	tlsCert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return nil, fmt.Errorf("parse identity cert/key: %w", err)
	}

	// Start from the system CA pool so controllers with publicly-trusted
	// certs (e.g. NetFoundry production) still verify. The Ziti CA from
	// the identity file is added on top.
	caPool, err := x509.SystemCertPool()
	if err != nil {
		caPool = x509.NewCertPool()
	}
	if caPEM != "" {
		if !caPool.AppendCertsFromPEM([]byte(caPEM)) {
			return nil, errors.New("no valid certificates in identity file CA")
		}
	}

	return &parsedIdentity{
		APIURL:  idFile.ZtAPI,
		TLSCert: tlsCert,
		CAPool:  caPool,
	}, nil
}

// discoveryClientFromIdentity builds an HTTP client that trusts the CA from
// the identity file but does not present a client certificate. This is used
// for unauthenticated calls to the public Edge Client API.
func discoveryClientFromIdentity(id *parsedIdentity) *http.Client {
	return tlsClient(&tls.Config{RootCAs: id.CAPool})
}

// managementClientFromIdentity builds an HTTP client with mTLS: the CA pool
// verifies the controller, and the client certificate authenticates ZDAS. This
// is used for the POST /authenticate call and subsequent management API calls.
func managementClientFromIdentity(id *parsedIdentity) *http.Client {
	return tlsClient(&tls.Config{
		Certificates: []tls.Certificate{id.TLSCert},
		RootCAs:      id.CAPool,
	})
}

// defaultAPISessionLifetime is how long an API session is assumed to last
// when the controller does not say.
const defaultAPISessionLifetime = 25 * time.Minute

// apiSession holds the result of a POST /authenticate call.
type apiSession struct {
	Token     string
	ExpiresAt time.Time
}

// authenticateSession authenticates with the client certificate to the
// management API at mgmtURL. It returns a session token that must be passed
// as the zt-session header on subsequent management API calls.
func authenticateSession(ctx context.Context, client *http.Client, mgmtURL string) (*apiSession, error) {
	authURL := mgmtURL + "/authenticate?method=cert"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, authURL, strings.NewReader("{}"))
	if err != nil {
		return nil, fmt.Errorf("build authenticate request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("authenticate request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("authenticate returned %d", resp.StatusCode)
	}

	var result struct {
		Data struct {
			Token             *string `json:"token"`
			ExpiresAt         string  `json:"expiresAt"`
			ExpirationSeconds *int    `json:"expirationSeconds"`
		} `json:"data"`
	}
	body, err := readResponseBody(resp)
	if err != nil {
		return nil, fmt.Errorf("read authenticate response: %w", err)
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("parse authenticate response: %w", err)
	}
	if result.Data.Token == nil || *result.Data.Token == "" {
		return nil, errors.New("api session token was empty")
	}

	expiresAt := time.Now().Add(defaultAPISessionLifetime)
	if result.Data.ExpirationSeconds != nil && *result.Data.ExpirationSeconds > 0 {
		expiresAt = time.Now().Add(time.Duration(*result.Data.ExpirationSeconds) * time.Second)
	} else if result.Data.ExpiresAt != "" {
		if t, err := time.Parse(time.RFC3339, result.Data.ExpiresAt); err == nil {
			expiresAt = t
		}
	}

	return &apiSession{Token: *result.Data.Token, ExpiresAt: expiresAt}, nil
}
