package oauth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"github.com/Elagoht/collage/pkg/collage"

	session "github.com/Elagoht/collage-session"
)

// pending is a sign-in that has left for the provider and not come back. The
// session holds one per provider, under pendingKey.
type pending struct {
	State    string `json:"s"`
	Nonce    string `json:"n"`
	Verifier string `json:"v"`
	Next     string `json:"x"`
	Created  int64  `json:"c"`
}

// maxNext is the longest next a sign-in keeps; a longer one is as good as none.
const maxNext = 1024

func pendingKey(name string) string { return "oauth:" + name }

// pendingFor reads the pending sign-in for the provider name from the request's
// session. It reports false when there is none, or no session at all.
func (p *Plugin) pendingFor(r *http.Request, name string) (pending, bool) {
	raw := session.FromContext(r.Context()).Get(pendingKey(name))
	if raw == "" {
		return pending{}, false
	}
	var pd pending
	if err := json.Unmarshal([]byte(raw), &pd); err != nil {
		return pending{}, false
	}
	return pd, true
}

// challenge is the S256 code_challenge of a PKCE verifier.
func challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// randomString is 32 random bytes, base64url-encoded without padding.
func randomString() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// redirectURI is the callback address the provider sends the reader back to. It
// follows the host the reader signed in on. "" means no origin can be told.
func (p *Plugin) redirectURI(r *http.Request, name string) string {
	var origin string
	if origins, ok := p.host.(collage.Origins); ok {
		origin = origins.OriginFor(r.Context(), r.Host)
	} else {
		origin = p.host.BaseURL()
	}
	if origin == "" {
		if !p.host.DevMode() {
			return ""
		}
		origin = "http://" + r.Host
	}
	return strings.TrimRight(origin, "/") + p.opts.Prefix + "/" + name + "/callback"
}

// fail ends a sign-in: to the application's error page with ?error=code when
// ErrorPath is set, else to the built-in status page.
func (p *Plugin) fail(w http.ResponseWriter, r *http.Request, code string, status int) {
	if p.opts.ErrorPath != "" {
		if u, err := url.Parse(p.opts.ErrorPath); err == nil {
			q := u.Query()
			q.Set("error", code)
			u.RawQuery = q.Encode()
			http.Redirect(w, r, u.String(), http.StatusSeeOther)
			return
		}
	}
	p.host.ServeStatus(w, r, status)
}

// login sends the reader to the provider, with a pending sign-in kept in the
// session for the callback to check.
func (p *Plugin) login(w http.ResponseWriter, r *http.Request, name string, pr *provider) {
	sess := session.FromContext(r.Context())
	if sess == nil {
		p.host.Logger().Error("elagoht/oauth needs elagoht/session in Config.Plugins")
		p.host.ServeStatus(w, r, http.StatusInternalServerError)
		return
	}
	redirect := p.redirectURI(r, name)
	if redirect == "" {
		p.host.Logger().Error("elagoht/oauth cannot tell its public origin: set Config.BaseURL")
		p.host.ServeStatus(w, r, http.StatusInternalServerError)
		return
	}
	md, err := p.discover(r.Context(), pr)
	if err != nil {
		p.host.Logger().Error("elagoht/oauth: discovery failed", "provider", name, "error", err)
		p.fail(w, r, "unavailable", http.StatusServiceUnavailable)
		return
	}
	endpoint, err := url.Parse(md.AuthorizationEndpoint)
	if err != nil {
		p.host.Logger().Error("elagoht/oauth: bad authorization_endpoint", "provider", name)
		p.fail(w, r, "unavailable", http.StatusServiceUnavailable)
		return
	}

	// The pending sign-in lives in the session cookie, so a long next (anyone can
	// send a reader to a login link) must not grow it.
	next := r.URL.Query().Get("next")
	if len(next) > maxNext {
		next = ""
	}
	pd := pending{
		Next:    collage.SafeRedirect(next, p.opts.AfterLogin),
		Created: p.clock().Unix(),
	}
	for _, dst := range []*string{&pd.State, &pd.Nonce, &pd.Verifier} {
		if *dst, err = randomString(); err != nil {
			p.host.Logger().Error("elagoht/oauth: no randomness", "error", err)
			p.host.ServeStatus(w, r, http.StatusInternalServerError)
			return
		}
	}
	raw, err := json.Marshal(pd)
	if err == nil {
		err = sess.Set(pendingKey(name), string(raw))
	}
	if err != nil {
		p.host.Logger().Error("elagoht/oauth: keeping the sign-in in the session failed", "error", err)
		p.host.ServeStatus(w, r, http.StatusInternalServerError)
		return
	}

	scopes := append([]string{"openid", "email", "profile"}, pr.cfg.Scopes...)
	if pr.cfg.Offline && pr.preset.offlineScope {
		scopes = append(scopes, "offline_access")
	}
	q := endpoint.Query()
	q.Set("response_type", "code")
	q.Set("client_id", pr.cfg.ClientID)
	q.Set("redirect_uri", redirect)
	q.Set("scope", strings.Join(uniqueScopes(scopes), " "))
	q.Set("state", pd.State)
	q.Set("nonce", pd.Nonce)
	q.Set("code_challenge", challenge(pd.Verifier))
	q.Set("code_challenge_method", "S256")
	if pr.cfg.Offline {
		for k, vs := range pr.preset.authParams {
			q[k] = vs
		}
	}
	endpoint.RawQuery = q.Encode()
	http.Redirect(w, r, endpoint.String(), http.StatusSeeOther)
}

func uniqueScopes(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := in[:0:0]
	for _, s := range in {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
