package zdas

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

// KeySet is an EC P-256 signing key pair plus its public JWK representation.
// By default NewServer generates one at startup, so a restart produces a new
// key and tokens signed with the old one become unverifiable. That is
// acceptable for a single instance because enrollment tokens are short-lived
// and single-use. Embedders that run several replicas, or want the key to
// survive restarts, load their own key with NewKeySet and pass it to
// WithKeySet.
type KeySet struct {
	private    *ecdsa.PrivateKey
	privateJWK jwk.Key // signs tokens, with kid and alg set
	publicJWK  jwk.Key
	kid        string
}

// GenerateKeySet creates a fresh EC P-256 key pair and wraps it in a KeySet.
// The key ID is the RFC 7638 JWK thumbprint of the public key, so it is
// deterministic and cryptographically bound to the key material.
func GenerateKeySet() (*KeySet, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ec key: %w", err)
	}
	return NewKeySet(priv)
}

// NewKeySet wraps an existing EC P-256 private key in a KeySet. The key ID is
// the RFC 7638 JWK thumbprint of the public key, as for GenerateKeySet. It
// rejects keys on any other curve and keys whose public half does not match
// the private scalar, either of which would publish a JWKS that cannot verify
// the tokens signed with it.
func NewKeySet(priv *ecdsa.PrivateKey) (*KeySet, error) {
	if priv == nil {
		return nil, errors.New("private key is nil")
	}
	if priv.Curve != elliptic.P256() {
		return nil, errors.New("private key is not on curve P-256")
	}
	ecdhPriv, err := priv.ECDH()
	if err != nil {
		return nil, fmt.Errorf("invalid private key: %w", err)
	}
	ecdhPub, err := priv.PublicKey.ECDH()
	if err != nil {
		return nil, fmt.Errorf("invalid public key: %w", err)
	}
	if !ecdhPriv.PublicKey().Equal(ecdhPub) {
		return nil, errors.New("public key does not match private key")
	}

	pub, err := jwk.FromRaw(priv.Public())
	if err != nil {
		return nil, fmt.Errorf("wrap public key as jwk: %w", err)
	}
	thumb, err := pub.Thumbprint(crypto.SHA256) // RFC 7638
	if err != nil {
		return nil, fmt.Errorf("compute jwk thumbprint: %w", err)
	}
	kid := base64.RawURLEncoding.EncodeToString(thumb)
	if err := pub.Set(jwk.KeyIDKey, kid); err != nil {
		return nil, fmt.Errorf("set kid: %w", err)
	}
	if err := pub.Set(jwk.AlgorithmKey, jwa.ES256); err != nil {
		return nil, fmt.Errorf("set alg: %w", err)
	}
	if err := pub.Set(jwk.KeyUsageKey, "sig"); err != nil {
		return nil, fmt.Errorf("set use: %w", err)
	}
	signing, err := jwk.FromRaw(priv)
	if err != nil {
		return nil, fmt.Errorf("wrap private key as jwk: %w", err)
	}
	if err := signing.Set(jwk.KeyIDKey, kid); err != nil {
		return nil, fmt.Errorf("set signing kid: %w", err)
	}
	if err := signing.Set(jwk.AlgorithmKey, jwa.ES256); err != nil {
		return nil, fmt.Errorf("set signing alg: %w", err)
	}
	return &KeySet{private: priv, privateJWK: signing, publicJWK: pub, kid: kid}, nil
}

// KID returns the key ID (JWK thumbprint) used to identify this key in JWS
// headers and in the JWKS document.
func (ks *KeySet) KID() string { return ks.kid }

// Private returns the raw ECDSA private key for signing operations.
func (ks *KeySet) Private() *ecdsa.PrivateKey { return ks.private }

// JWKS returns the marshaled JWKS JSON publishing the public key of each set
// once, in order, with kid, alg and use set: the document ZDAS's own JWKS
// endpoint serves for WithKeySet(sets[0], sets[1:]...). An embedder that
// serves keys on its own, for example to a controller that cannot reach
// ZDAS, passes the active key first, then every verify-only key. It fails
// on no sets or a nil one.
func JWKS(sets ...*KeySet) ([]byte, error) {
	if len(sets) == 0 {
		return nil, errors.New("JWKS: no key sets")
	}
	if slices.Contains(sets, nil) {
		return nil, errors.New("JWKS: nil key set")
	}
	return publicJWKS(uniqueKeySets(sets[0], sets[1:]))
}

// publicJWKS returns the marshaled JWKS JSON containing the public key of
// every given key set, in order.
func publicJWKS(sets []*KeySet) ([]byte, error) {
	set := jwk.NewSet()
	for _, ks := range sets {
		if err := set.AddKey(ks.publicJWK); err != nil {
			return nil, fmt.Errorf("add key %s to set: %w", ks.kid, err)
		}
	}
	return json.Marshal(set)
}

// uniqueKeySets returns active followed by each verifyOnly key whose kid has
// not already appeared. The kid is the key's thumbprint, so equal kids mean
// the same public key and the duplicate adds nothing to the JWKS.
func uniqueKeySets(active *KeySet, verifyOnly []*KeySet) []*KeySet {
	out := []*KeySet{active}
	seen := map[string]struct{}{active.kid: {}}
	for _, ks := range verifyOnly {
		if _, dup := seen[ks.kid]; dup {
			continue
		}
		seen[ks.kid] = struct{}{}
		out = append(out, ks)
	}
	return out
}
