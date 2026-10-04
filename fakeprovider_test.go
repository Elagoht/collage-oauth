// The fake OIDC provider every oauth test uses.
//
// Package choice: package oauth (internal). Tests of later tasks are internal
// too, so they reach unexported code (discover, provider, ...) and this fake
// without export hooks. Do not write external (oauth_test) tests that need it.
//
// Typical use:
//
//	fp := newFakeProvider(t)            // TLS server, closed with t.Cleanup
//	fp.ExpectCode("code-1", nonce)      // what /authorize would have recorded
//	fp.RememberChallenge("code-1", ch)  // PKCE challenge seen on /authorize
//	cfg := Provider{Name: "fake", Issuer: fp.URL, ClientID: "client", ClientSecret: "secret"}
//	opts.HTTPClient = fp.Client         // trusts the fake's certificate
//
// The fake accepts Basic auth client:secret only. Knobs may be set before the
// first request; counters and Revoked are safe to read at any time via the
// accessors below.
package oauth

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeProvider struct {
	URL    string
	Client *http.Client

	// IDTokenClaims override the default claims. A value starting with "[" is
	// written raw (an aud array). Numeric claims (exp, iat) are overridable
	// through IDTokenNumbers. email_verified is raw JSON: "false".
	IDTokenClaims  map[string]string
	IDTokenNumbers map[string]int64
	// Issuer, when set, is what the discovery document claims as its issuer.
	Issuer string
	// DiscoveryStatus, when non-zero, is answered instead of the document.
	DiscoveryStatus int
	// TokenStatus, when non-zero, is answered by /token for the code grant.
	TokenStatus int
	// Refresh answers grant_type=refresh_token. Nil: 400.
	Refresh func(refreshToken string) (newAccess, newRefresh string, status int)
	// UserinfoSub is the "sub" /userinfo answers. Default "u-1".
	UserinfoSub string
	// ClientID and ClientSecret are what /token expects. Defaults "client", "secret".
	ClientID, ClientSecret string

	TokenCalls     atomic.Int32
	RefreshCalls   atomic.Int32
	DiscoveryCalls atomic.Int32

	mu         sync.Mutex
	nonces     map[string]string // code -> nonce
	challenges map[string]string // code -> PKCE challenge
	revoked    []string

	srv *httptest.Server
}

func newFakeProvider(t *testing.T) *fakeProvider {
	t.Helper()
	f := &fakeProvider{
		ClientID: "client", ClientSecret: "secret",
		nonces: map[string]string{}, challenges: map[string]string{},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", f.discovery)
	mux.HandleFunc("/token", f.token)
	mux.HandleFunc("/userinfo", f.userinfo)
	mux.HandleFunc("/revoke", f.revoke)
	f.srv = httptest.NewTLSServer(mux)
	t.Cleanup(f.srv.Close)
	f.URL = f.srv.URL
	f.Client = f.srv.Client()
	return f
}

// ExpectCode registers the nonce the id_token of this code carries.
func (f *fakeProvider) ExpectCode(code, nonce string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nonces[code] = nonce
}

// RememberChallenge records the PKCE code_challenge sent on /authorize for code.
// /token then requires the code_verifier to hash (S256) to it.
func (f *fakeProvider) RememberChallenge(code, challenge string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.challenges[code] = challenge
}

// Revoked returns the tokens /revoke has seen.
func (f *fakeProvider) Revoked() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.revoked...)
}

func writeJSON[T fakeDiscovery | fakeTokenResponse | fakeUserinfo](w http.ResponseWriter, status int, v T) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

type fakeDiscovery struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	UserinfoEndpoint      string   `json:"userinfo_endpoint"`
	RevocationEndpoint    string   `json:"revocation_endpoint"`
	TokenAuthMethods      []string `json:"token_endpoint_auth_methods_supported"`
}

func (f *fakeProvider) discovery(w http.ResponseWriter, _ *http.Request) {
	f.DiscoveryCalls.Add(1)
	if f.DiscoveryStatus != 0 {
		http.Error(w, "nope", f.DiscoveryStatus)
		return
	}
	issuer := f.URL
	if f.Issuer != "" {
		issuer = f.Issuer
	}
	writeJSON(w, http.StatusOK, fakeDiscovery{
		Issuer:                issuer,
		AuthorizationEndpoint: f.URL + "/authorize",
		TokenEndpoint:         f.URL + "/token",
		UserinfoEndpoint:      f.URL + "/userinfo",
		RevocationEndpoint:    f.URL + "/revoke",
		TokenAuthMethods:      []string{"client_secret_basic"},
	})
}

type fakeTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	ExpiresIn    int    `json:"expires_in"`
	IDToken      string `json:"id_token,omitempty"`
	TokenType    string `json:"token_type"`
}

func (f *fakeProvider) token(w http.ResponseWriter, r *http.Request) {
	id, secret, ok := r.BasicAuth()
	if !ok || id != f.ClientID || secret != f.ClientSecret {
		http.Error(w, `{"error":"invalid_client"}`, http.StatusUnauthorized)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
		f.TokenCalls.Add(1)
		f.codeGrant(w, r.PostForm)
	case "refresh_token":
		f.RefreshCalls.Add(1)
		if f.Refresh == nil {
			http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
			return
		}
		access, refresh, status := f.Refresh(r.PostForm.Get("refresh_token"))
		if status != 0 && status != http.StatusOK {
			http.Error(w, `{"error":"invalid_grant"}`, status)
			return
		}
		writeJSON(w, http.StatusOK, fakeTokenResponse{AccessToken: access, RefreshToken: refresh, ExpiresIn: 3600, TokenType: "Bearer"})
	default:
		http.Error(w, `{"error":"unsupported_grant_type"}`, http.StatusBadRequest)
	}
}

func (f *fakeProvider) codeGrant(w http.ResponseWriter, form url.Values) {
	if f.TokenStatus != 0 && f.TokenStatus != http.StatusOK {
		http.Error(w, `{"error":"invalid_grant"}`, f.TokenStatus)
		return
	}
	code := form.Get("code")
	f.mu.Lock()
	nonce, known := f.nonces[code]
	challenge, hasChallenge := f.challenges[code]
	f.mu.Unlock()
	if !known {
		http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
		return
	}
	if hasChallenge && pkceChallenge(form.Get("code_verifier")) != challenge {
		http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, fakeTokenResponse{
		AccessToken: "access-" + code, RefreshToken: "refresh-" + code, ExpiresIn: 3600,
		IDToken: f.idToken(nonce), TokenType: "Bearer",
	})
}

func (f *fakeProvider) idToken(nonce string) string {
	now := time.Now()
	strs := map[string]string{
		"iss": f.URL, "aud": f.ClientID, "nonce": nonce, "sub": "u-1",
		"email": "a@b.c", "name": "A",
	}
	for k, v := range f.IDTokenClaims {
		strs[k] = v
	}
	nums := map[string]int64{"exp": now.Add(5 * time.Minute).Unix(), "iat": now.Unix()}
	for k, v := range f.IDTokenNumbers {
		nums[k] = v
	}
	raw := map[string]json.RawMessage{"email_verified": json.RawMessage("true")}
	for k, v := range strs {
		switch {
		case k == "email_verified" || (len(v) > 0 && v[0] == '['):
			raw[k] = json.RawMessage(v)
		default:
			b, _ := json.Marshal(v)
			raw[k] = b
		}
	}
	for k, v := range nums {
		raw[k] = json.RawMessage(strconv.FormatInt(v, 10))
	}
	claims, _ := json.Marshal(raw)
	header, _ := json.Marshal(map[string]string{"alg": "none", "typ": "JWT"})
	enc := base64.RawURLEncoding
	return enc.EncodeToString(header) + "." + enc.EncodeToString(claims) + "."
}

// pkceChallenge is the S256 code_challenge of a verifier.
func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

type fakeUserinfo struct {
	Sub           string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
}

func (f *fakeProvider) userinfo(w http.ResponseWriter, _ *http.Request) {
	sub := f.UserinfoSub
	if sub == "" {
		sub = "u-1"
	}
	writeJSON(w, http.StatusOK, fakeUserinfo{Sub: sub, Email: "a@b.c", EmailVerified: true})
}

func (f *fakeProvider) revoke(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	f.mu.Lock()
	f.revoked = append(f.revoked, r.PostForm.Get("token"))
	f.mu.Unlock()
	w.WriteHeader(http.StatusOK)
}
