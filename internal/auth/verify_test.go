package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// signer mints real RS256 tokens against a throwaway key and serves the
// matching JWKS, so these tests exercise the actual verification path
// rather than a stub.
type signer struct {
	key *rsa.PrivateKey
	kid string
}

func newSigner(t *testing.T) *signer {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return &signer{key: k, kid: "test-key-1"}
}

func (s *signer) jwksServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e := big.NewInt(int64(s.key.E)).Bytes()
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]any{{
				"kty": "RSA", "use": "sig", "alg": "RS256", "kid": s.kid,
				"n": base64.RawURLEncoding.EncodeToString(s.key.N.Bytes()),
				"e": base64.RawURLEncoding.EncodeToString(e),
			}},
		})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func (s *signer) token(t *testing.T, claims map[string]any) string {
	t.Helper()
	return s.tokenWithHeader(t, map[string]any{"alg": "RS256", "typ": "JWT", "kid": s.kid}, claims)
}

func (s *signer) tokenWithHeader(t *testing.T, header, claims map[string]any) string {
	t.Helper()
	enc := func(v any) string {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(b)
	}
	signing := enc(header) + "." + enc(claims)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, s.key, 5, sum[:]) // 5 = crypto.SHA256
	if err != nil {
		t.Fatal(err)
	}
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func baseClaims() map[string]any {
	now := time.Now()
	return map[string]any{
		"iss":       "https://auth.kelliher.info",
		"sub":       "user-abc",
		"client_id": "herald",
		"exp":       now.Add(time.Hour).Unix(),
		"iat":       now.Unix(),
		"nbf":       now.Add(-time.Minute).Unix(),
		"scp":       []string{"openid", "profile", "groups"},
		"groups":    []string{"admins"},
	}
}

func newVerifier(s *signer, t *testing.T) *Verifier {
	return &Verifier{
		JWKSURL:   s.jwksServer(t).URL,
		Issuer:    "https://auth.kelliher.info",
		ClientIDs: []string{"herald"},
	}
}

func TestVerifyAcceptsGoodToken(t *testing.T) {
	s := newSigner(t)
	v := newVerifier(s, t)

	id, err := v.Verify(context.Background(), "Bearer "+s.token(t, baseClaims()))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if id.Subject != "user-abc" || id.ClientID != "herald" {
		t.Errorf("identity = %+v", id)
	}
	if !id.HasGroup("admins") {
		t.Errorf("groups = %v", id.Groups)
	}
	// Authelia spells the scope claim "scp"; the RFC spells it "scope".
	if len(id.Scopes) != 3 {
		t.Errorf("scopes = %v", id.Scopes)
	}
}

// The load-bearing check. Authelia issues an empty aud, so client_id is the
// only thing standing between one service's token and another's API.
func TestVerifyRejectsAnotherClientsToken(t *testing.T) {
	s := newSigner(t)
	v := newVerifier(s, t)

	claims := baseClaims()
	claims["client_id"] = "kfin" // a perfectly valid token — for kfin

	_, err := v.Verify(context.Background(), "Bearer "+s.token(t, claims))
	if err == nil {
		t.Fatal("a kfin token must not open herald")
	}
	if !strings.Contains(err.Error(), "kfin") {
		t.Errorf("error should name the offending client: %v", err)
	}
}

func TestVerifyRejectsMissingClientID(t *testing.T) {
	s := newSigner(t)
	v := newVerifier(s, t)
	claims := baseClaims()
	delete(claims, "client_id")

	if _, err := v.Verify(context.Background(), "Bearer "+s.token(t, claims)); err == nil {
		t.Fatal("a token with no client_id must be refused")
	}
}

// The "alg: none" family: the token must not choose how it is checked.
func TestVerifyRejectsAlgNone(t *testing.T) {
	s := newSigner(t)
	v := newVerifier(s, t)

	tok := s.tokenWithHeader(t,
		map[string]any{"alg": "none", "typ": "JWT", "kid": s.kid}, baseClaims())
	if _, err := v.Verify(context.Background(), "Bearer "+tok); err == nil {
		t.Fatal("alg=none must be refused")
	}
}

func TestVerifyRejectsForgedSignature(t *testing.T) {
	s := newSigner(t)
	other := newSigner(t)
	other.kid = s.kid // claim to be the real key
	v := newVerifier(s, t)

	if _, err := v.Verify(context.Background(), "Bearer "+other.token(t, baseClaims())); err == nil {
		t.Fatal("a token signed by the wrong key must be refused")
	}
}

func TestVerifyRejectsExpiredAndWrongIssuer(t *testing.T) {
	s := newSigner(t)
	v := newVerifier(s, t)

	expired := baseClaims()
	expired["exp"] = time.Now().Add(-2 * time.Hour).Unix()
	if _, err := v.Verify(context.Background(), "Bearer "+s.token(t, expired)); err == nil {
		t.Error("expired token must be refused")
	}

	wrongIss := baseClaims()
	wrongIss["iss"] = "https://evil.example"
	if _, err := v.Verify(context.Background(), "Bearer "+s.token(t, wrongIss)); err == nil {
		t.Error("token from another issuer must be refused")
	}
}

func TestVerifyRejectsMalformed(t *testing.T) {
	s := newSigner(t)
	v := newVerifier(s, t)
	for _, h := range []string{"", "Bearer", "Bearer ", "Basic abc", "Bearer not.a.jwt"} {
		if _, err := v.Verify(context.Background(), h); err == nil {
			t.Errorf("header %q must be refused", h)
		}
	}
}

// An unknown kid triggers at most one refetch per minute, so a bogus token
// cannot be turned into a request amplifier against Authelia.
func TestUnknownKidDoesNotHammerJWKS(t *testing.T) {
	s := newSigner(t)
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		_, _ = w.Write([]byte(`{"keys":[]}`))
	}))
	t.Cleanup(srv.Close)

	v := &Verifier{JWKSURL: srv.URL, Issuer: "https://auth.kelliher.info", ClientIDs: []string{"herald"}}
	for i := 0; i < 5; i++ {
		_, _ = v.Verify(context.Background(), "Bearer "+s.token(t, baseClaims()))
	}
	if hits > 1 {
		t.Errorf("JWKS fetched %d times for repeated unknown kids; want at most 1", hits)
	}
}
