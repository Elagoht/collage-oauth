package oauth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Elagoht/collage/pkg/collage"

	session "github.com/Elagoht/collage-session"
)

// pending is a sign-in that has left for the provider and not come back. It is
// kept in a cookie of its own, pendingCookieName, one per provider.
type pending struct {
	State    string `json:"s"`
	Nonce    string `json:"n"`
	Verifier string `json:"v"`
	Next     string `json:"x"`
	Created  int64  `json:"c"`
}

// maxNext is the longest next a sign-in keeps; a longer one is as good as none.
const maxNext = 1024

// pendingCookieName is the cookie a pending sign-in is kept in. Each provider's
// has its own Path, {prefix}/{provider}/, so two sign-ins do not meet.
//
// It is not the session: a session is signed, lasts MaxAge and turns the page
// cache off, and anybody can start a sign-in. The cookie lives pendingTTL, is
// sent only to the provider's login and callback routes, and nothing reads it
// but the callback, which deletes it. It is not signed, because a signature
// would add nothing: what it guards against is a cookie planted in a reader's
// browser, and an attacker can plant a signed one as easily, by starting a
// sign-in of their own. next is checked again before it is a Location.
const pendingCookieName = "collage_oauth"

// maxPendingCookie is the most the pending cookie's name and value may take
// together: what every browser keeps of one cookie.
const maxPendingCookie = 4096

// pendingPath is the Path of the provider name's pending cookie.
func (p *Plugin) pendingPath(name string) string {
	return p.opts.Prefix + "/" + url.PathEscape(name) + "/"
}

// pendingFor reads the pending sign-in for the provider name from the
// request's cookie. It reports false when there is none, or none that decodes.
func (p *Plugin) pendingFor(r *http.Request, name string) (pending, bool) {
	c, err := r.Cookie(pendingCookieName)
	if err != nil {
		return pending{}, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(c.Value)
	if err != nil {
		return pending{}, false
	}
	var pd pending
	if err := json.Unmarshal(raw, &pd); err != nil {
		return pending{}, false
	}
	return pd, true
}

// pendingCookie is the provider name's pending cookie holding value, for
// maxAge seconds; a negative maxAge deletes it.
func (p *Plugin) pendingCookie(r *http.Request, name, value string, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name:     pendingCookieName,
		Value:    value,
		Path:     p.pendingPath(name),
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   collage.IsHTTPS(r),
		SameSite: http.SameSiteLaxMode,
	}
}

// clearPending deletes the provider name's pending cookie.
func (p *Plugin) clearPending(w http.ResponseWriter, r *http.Request, name string) {
	http.SetCookie(w, p.pendingCookie(r, name, "", -1))
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
	origin := p.host.OriginFor(r.Context(), r.Host)
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
			seeOther(w, u.String())
			return
		}
	}
	p.host.ServeStatus(w, r, status)
}

// login sends the reader to the provider, with a pending sign-in kept in a
// cookie for the callback to check. It starts no session.
func (p *Plugin) login(w http.ResponseWriter, r *http.Request, name string, pr *provider) {
	if session.FromContext(r.Context()) == nil {
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

	// The pending sign-in lives in a cookie, so a long next (anyone can send a
	// reader to a login link) must not grow it.
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
	value, err := p.pendingValue(pd)
	if err != nil {
		p.host.Logger().Error("elagoht/oauth: keeping the sign-in failed", "error", err)
		p.host.ServeStatus(w, r, http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, p.pendingCookie(r, name, value, int(pendingTTL/time.Second)))

	scopes := requestedScopes(pr)
	q := endpoint.Query()
	q.Set("response_type", "code")
	q.Set("client_id", pr.cfg.ClientID)
	q.Set("redirect_uri", redirect)
	q.Set("scope", strings.Join(scopes, " "))
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
	seeOther(w, endpoint.String())
}

// pendingValue is pd as the pending cookie's value. When the cookie would be
// more than a browser keeps, the sign-in is kept without its next, ending at
// AfterLogin: a next under maxNext whose characters JSON escapes can still be
// too much.
func (p *Plugin) pendingValue(pd pending) (string, error) {
	raw, err := encodePending(pd)
	if err != nil {
		return "", err
	}
	value := base64.RawURLEncoding.EncodeToString([]byte(raw))
	if len(pendingCookieName)+len(value) <= maxPendingCookie || pd.Next == p.opts.AfterLogin {
		return value, nil
	}
	pd.Next = p.opts.AfterLogin
	if raw, err = encodePending(pd); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString([]byte(raw)), nil
}

// requestedScopes is what login asks the provider for, and what a token is
// recorded as holding when the provider does not say.
func requestedScopes(pr *provider) []string {
	scopes := append([]string{"openid", "email", "profile"}, pr.cfg.Scopes...)
	// Without a preset the provider is plain OpenID Connect, where the
	// offline_access scope is how a refresh token is asked for (Core 11).
	if pr.cfg.Offline && (pr.preset.offlineScope || pr.cfg.Preset == "") {
		scopes = append(scopes, "offline_access")
	}
	return uniqueScopes(scopes)
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

// encodePending is pd as JSON without HTML escapes, so "<" stays one byte in a
// cookie that has a size limit.
func encodePending(pd pending) (string, error) {
	var b strings.Builder
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(pd); err != nil {
		return "", err
	}
	return strings.TrimSuffix(b.String(), "\n"), nil
}
