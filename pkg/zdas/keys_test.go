package zdas

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

func TestGenerateKeySet(t *testing.T) {
	ks, err := GenerateKeySet()
	if err != nil {
		t.Fatalf("GenerateKeySet: %v", err)
	}

	// Private key should be P-256.
	if ks.Private().Curve != elliptic.P256() {
		t.Error("expected P-256 curve")
	}
	if ks.KID() == "" {
		t.Error("kid is empty")
	}

	// Public JWK should carry the right metadata.
	k := ks.publicJWK
	if k.KeyType().String() != "EC" {
		t.Errorf("key type = %q, want EC", k.KeyType())
	}
	if alg, _ := k.Algorithm(); alg.String() != jwa.ES256().String() {
		t.Errorf("algorithm = %q, want ES256", alg)
	}
	if kid, _ := k.KeyID(); kid != ks.KID() {
		t.Errorf("kid on jwk = %q, want %q", kid, ks.KID())
	}

	// Should not contain private material.
	var raw ecdsa.PublicKey
	if err := jwk.Export(k, &raw); err != nil {
		t.Fatalf("extract raw public key: %v", err)
	}
}

func TestJWKS(t *testing.T) {
	ks, err := GenerateKeySet()
	if err != nil {
		t.Fatalf("GenerateKeySet: %v", err)
	}
	data, err := JWKS(ks)
	if err != nil {
		t.Fatalf("JWKS: %v", err)
	}

	// Must be valid JSON with a "keys" array containing one element.
	var doc struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("unmarshal JWKS: %v", err)
	}
	if len(doc.Keys) != 1 {
		t.Fatalf("keys count = %d, want 1", len(doc.Keys))
	}
}

func TestSignAndVerifyRoundtrip(t *testing.T) {
	ks, err := GenerateKeySet()
	if err != nil {
		t.Fatalf("GenerateKeySet: %v", err)
	}
	payload := []byte(`{"sub":"test"}`)

	// Sign with private key using ES256.
	privJWK, err := jwk.Import(ks.Private())
	if err != nil {
		t.Fatalf("wrap private key: %v", err)
	}
	if err := privJWK.Set(jwk.KeyIDKey, ks.KID()); err != nil {
		t.Fatalf("set kid on private jwk: %v", err)
	}
	if err := privJWK.Set(jwk.AlgorithmKey, jwa.ES256()); err != nil {
		t.Fatalf("set alg on private jwk: %v", err)
	}

	signed, err := jws.Sign(payload, jws.WithKey(jwa.ES256(), privJWK))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	// Verify using just the public JWKS (what the controller would do).
	jwksBytes, err := JWKS(ks)
	if err != nil {
		t.Fatalf("JWKS: %v", err)
	}
	pubSet, err := jwk.Parse(jwksBytes)
	if err != nil {
		t.Fatalf("parse JWKS: %v", err)
	}
	verified, err := jws.Verify(signed, jws.WithKeySet(pubSet))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if string(verified) != string(payload) {
		t.Errorf("verified payload = %q, want %q", verified, payload)
	}
}

func TestTwoKeySetsProduceDifferentKeys(t *testing.T) {
	ks1, err := GenerateKeySet()
	if err != nil {
		t.Fatalf("GenerateKeySet 1: %v", err)
	}
	ks2, err := GenerateKeySet()
	if err != nil {
		t.Fatalf("GenerateKeySet 2: %v", err)
	}
	if ks1.KID() == ks2.KID() {
		t.Error("two independently generated key sets have the same kid")
	}
}

func TestNewKeySetKIDIsThumbprint(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	ks, err := NewKeySet(priv)
	if err != nil {
		t.Fatalf("NewKeySet: %v", err)
	}
	if ks.Private() != priv {
		t.Error("Private() does not return the wrapped key")
	}

	// Compute the RFC 7638 thumbprint independently of NewKeySet.
	pub, err := jwk.Import(priv.Public())
	if err != nil {
		t.Fatalf("wrap public key: %v", err)
	}
	thumb, err := pub.Thumbprint(crypto.SHA256)
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}
	if want := base64.RawURLEncoding.EncodeToString(thumb); ks.KID() != want {
		t.Errorf("kid = %q, want thumbprint %q", ks.KID(), want)
	}

	// The same key wrapped twice yields the same kid.
	again, err := NewKeySet(priv)
	if err != nil {
		t.Fatalf("NewKeySet again: %v", err)
	}
	if again.KID() != ks.KID() {
		t.Errorf("kid not deterministic: %q then %q", ks.KID(), again.KID())
	}
}

func TestNewKeySetRejectsInvalidKeys(t *testing.T) {
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P-384 key: %v", err)
	}
	a, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key a: %v", err)
	}
	b, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key b: %v", err)
	}
	// a's private key with b's public half.
	mismatched := *a
	mismatched.PublicKey = b.PublicKey

	for name, priv := range map[string]*ecdsa.PrivateKey{
		"nil":        nil,
		"P-384":      p384,
		"mismatched": &mismatched,
	} {
		if _, err := NewKeySet(priv); err == nil {
			t.Errorf("%s: NewKeySet succeeded, want error", name)
		}
	}
}

func TestNewKeySetJWKSRoundTrip(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	ks, err := NewKeySet(priv)
	if err != nil {
		t.Fatalf("NewKeySet: %v", err)
	}
	data, err := JWKS(ks)
	if err != nil {
		t.Fatalf("JWKS: %v", err)
	}
	set, err := jwk.Parse(data)
	if err != nil {
		t.Fatalf("parse JWKS: %v", err)
	}
	if set.Len() != 1 {
		t.Fatalf("keys count = %d, want 1", set.Len())
	}
	key, ok := set.LookupKeyID(ks.KID())
	if !ok {
		t.Fatalf("kid %q not in JWKS", ks.KID())
	}
	var raw ecdsa.PublicKey
	if err := jwk.Export(key, &raw); err != nil {
		t.Fatalf("extract raw public key: %v", err)
	}
	if !raw.Equal(&priv.PublicKey) {
		t.Error("JWKS public key does not match the wrapped key")
	}
}

func TestPublicJWKSMultipleKeys(t *testing.T) {
	sets := make([]*KeySet, 3)
	for i := range sets {
		ks, err := GenerateKeySet()
		if err != nil {
			t.Fatalf("GenerateKeySet: %v", err)
		}
		sets[i] = ks
	}
	data, err := publicJWKS(uniqueKeySets(sets[0], sets[1:]))
	if err != nil {
		t.Fatalf("publicJWKS: %v", err)
	}
	pubSet, err := jwk.Parse(data)
	if err != nil {
		t.Fatalf("parse JWKS: %v", err)
	}
	if pubSet.Len() != 3 {
		t.Fatalf("keys count = %d, want 3", pubSet.Len())
	}

	tokenCfg := TokenConfig{Issuer: "https://zdas.test", Audience: "ziti", Expiry: time.Minute}
	for i, ks := range sets {
		if _, ok := pubSet.LookupKeyID(ks.KID()); !ok {
			t.Errorf("key %d: kid %q not in JWKS", i, ks.KID())
		}
		signed, err := MintToken(tokenCfg, map[string]any{"sub": "x"}, ks)
		if err != nil {
			t.Fatalf("key %d: MintToken: %v", i, err)
		}
		if _, err := jwt.Parse([]byte(signed), jwt.WithKeySet(pubSet)); err != nil {
			t.Errorf("key %d: verify against JWKS: %v", i, err)
		}
	}
}

func TestUniqueKeySetsDropsDuplicateKIDs(t *testing.T) {
	a, err := GenerateKeySet()
	if err != nil {
		t.Fatalf("GenerateKeySet: %v", err)
	}
	b, err := GenerateKeySet()
	if err != nil {
		t.Fatalf("GenerateKeySet: %v", err)
	}
	// A second KeySet wrapping a's key has a's kid.
	aAgain, err := NewKeySet(a.Private())
	if err != nil {
		t.Fatalf("NewKeySet: %v", err)
	}
	got := uniqueKeySets(a, []*KeySet{b, aAgain, b})
	if len(got) != 2 || got[0] != a || got[1] != b {
		kids := make([]string, len(got))
		for i, ks := range got {
			kids[i] = ks.KID()
		}
		t.Errorf("uniqueKeySets = %v, want [%s %s]", kids, a.KID(), b.KID())
	}
}

// TestJWKSDeduplicatesAndRejectsNil verifies that JWKS publishes a key once
// however often it is passed, as the ZDAS endpoint does, and fails rather
// than panicking on a nil set.
func TestJWKSDeduplicatesAndRejectsNil(t *testing.T) {
	a, err := GenerateKeySet()
	if err != nil {
		t.Fatal(err)
	}
	b, err := GenerateKeySet()
	if err != nil {
		t.Fatal(err)
	}
	data, err := JWKS(a, b, a)
	if err != nil {
		t.Fatalf("JWKS: %v", err)
	}
	set, err := jwk.Parse(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if set.Len() != 2 {
		t.Errorf("JWKS holds %d keys, want 2", set.Len())
	}
	for _, sets := range [][]*KeySet{nil, {nil}, {a, nil}} {
		if _, err := JWKS(sets...); err == nil {
			t.Errorf("JWKS(%v) succeeded", sets)
		}
	}
}
