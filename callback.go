package oauth

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/Elagoht/collage/pkg/collage"

	session "github.com/Elagoht/collage-session"
)

// pendingTTL is how long a sign-in may stay at the provider.
const pendingTTL = 10 * time.Minute

// maxResponse is the most the plugin reads of a provider's answer.
const maxResponse = 1 << 20

// tokenResponse is the token endpoint's answer.
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
}

// callback ends a sign-in the provider sent back: it checks the pending sign-in
// and the id_token, asks OnLogin for the user, and signs the session in. Any
// failure ends the sign-in with no one signed in.
func (p *Plugin) callback(w http.ResponseWriter, r *http.Request, name string, pr *provider) {
	ctx := r.Context()
	sess := session.FromContext(ctx)
	if sess == nil {
		p.host.Logger().Error("elagoht/oauth needs elagoht/session in Config.Plugins")
		p.host.ServeStatus(w, r, http.StatusInternalServerError)
		return
	}

	// Used once: gone before anything is checked, whatever the outcome.
	pd, ok := p.pendingFor(r, name)
	sess.Delete(pendingKey(name))
	if !ok {
		p.fail(w, r, "state", http.StatusBadRequest)
		return
	}
	if p.clock().Sub(time.Unix(pd.Created, 0)) > pendingTTL {
		p.fail(w, r, "expired", http.StatusBadRequest)
		return
	}
	q := r.URL.Query()
	if q.Get("error") != "" {
		p.fail(w, r, "denied", http.StatusBadRequest)
		return
	}
	if pd.State == "" || subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(pd.State)) != 1 {
		p.fail(w, r, "state", http.StatusBadRequest)
		return
	}
	code := q.Get("code")
	if code == "" {
		p.fail(w, r, "exchange", http.StatusBadGateway)
		return
	}

	redirect := p.redirectURI(r, name)
	if redirect == "" {
		p.host.Logger().Error("elagoht/oauth cannot tell its public origin: set Config.BaseURL")
		p.host.ServeStatus(w, r, http.StatusInternalServerError)
		return
	}
	meta, err := p.discover(ctx, pr)
	if err != nil {
		p.host.Logger().Error("elagoht/oauth: discovery failed", "provider", name, "error", err)
		p.fail(w, r, "unavailable", http.StatusServiceUnavailable)
		return
	}
	tok, err := p.exchange(ctx, pr, meta, code, pd.Verifier, redirect)
	if err != nil {
		p.host.Logger().Warn("elagoht/oauth: code exchange failed", "provider", name, "error", err)
		p.fail(w, r, "exchange", http.StatusBadGateway)
		return
	}

	c, err := parseIDToken(tok.IDToken)
	if err == nil {
		err = checkClaims(c, pr, meta, pr.cfg.ClientID, pd.Nonce, p.clock())
	}
	if err != nil {
		p.host.Logger().Warn("elagoht/oauth: id_token refused", "provider", name, "error", err)
		p.fail(w, r, "token", http.StatusBadGateway)
		return
	}
	id := Identity{
		Provider: name, Subject: c.Sub,
		Email: c.Email, EmailVerified: c.EmailVerified, Name: c.Name, Picture: c.Picture,
	}
	if c.Email == "" && meta.UserinfoEndpoint != "" {
		info, err := p.userinfo(ctx, meta, tok.AccessToken)
		if err != nil {
			p.host.Logger().Warn("elagoht/oauth: userinfo failed", "provider", name, "error", err)
			p.fail(w, r, "exchange", http.StatusBadGateway)
			return
		}
		if subtle.ConstantTimeCompare([]byte(info.Sub), []byte(c.Sub)) != 1 {
			p.host.Logger().Warn("elagoht/oauth: userinfo sub is not the id_token's", "provider", name)
			p.fail(w, r, "token", http.StatusBadGateway)
			return
		}
		id.Email, id.EmailVerified = info.Email, info.EmailVerified
		if id.Name == "" {
			id.Name = info.Name
		}
		if id.Picture == "" {
			id.Picture = info.Picture
		}
	}

	userID, err := p.opts.OnLogin(ctx, id)
	if err != nil || userID == "" {
		p.fail(w, r, "rejected", http.StatusBadRequest)
		return
	}
	if err := p.signIn(ctx, sess, name, userID, tok); err != nil {
		p.host.Logger().Error("elagoht/oauth: signing the session in failed", "provider", name, "error", err)
		p.host.ServeStatus(w, r, http.StatusInternalServerError)
		return
	}
	// The session cookie is signed, so next is what login stored; checked again
	// all the same, since it is about to be a Location.
	http.Redirect(w, r, collage.SafeRedirect(pd.Next, p.opts.AfterLogin), http.StatusSeeOther)
}

// signIn gives the session a new ID, so one planted before the sign-in holds
// nothing after it, and stores the user under session.UserKey. Task 6 keeps the
// provider's tokens here. A failed Set changes nothing, so no one is signed in.
func (p *Plugin) signIn(_ context.Context, sess *session.Session, _, userID string, _ *tokenResponse) error {
	sess.Regenerate()
	// Task 6: with a Store, seal tok and Save it here.
	return sess.Set(session.UserKey, userID)
}

// exchange trades an authorization code for tokens at the token endpoint.
func (p *Plugin) exchange(ctx context.Context, pr *provider, meta *metadata, code, verifier, redirectURI string) (*tokenResponse, error) {
	return p.tokenRequest(ctx, pr, meta, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"code_verifier": {verifier},
	})
}

// tokenRequest POSTs form to the token endpoint with the client's credentials:
// HTTP Basic when the provider lists client_secret_basic or lists nothing, form
// fields otherwise. The answer must be a 200 of at most 1 MiB with an access
// token. Errors carry the status at most, never the body.
func (p *Plugin) tokenRequest(ctx context.Context, pr *provider, meta *metadata, form url.Values) (*tokenResponse, error) {
	basic := len(meta.TokenAuthMethods) == 0 || slices.Contains(meta.TokenAuthMethods, "client_secret_basic")
	if !basic {
		form.Set("client_id", pr.cfg.ClientID)
		form.Set("client_secret", pr.secret)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, meta.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, errors.New("oauth: bad token endpoint")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if basic {
		// RFC 6749 2.3.1: both are form-encoded before Basic.
		req.SetBasicAuth(url.QueryEscape(pr.cfg.ClientID), url.QueryEscape(pr.secret))
	}
	resp, err := p.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("oauth: token endpoint: %w", stripURL(err))
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponse))
		return nil, fmt.Errorf("oauth: token endpoint answered %d", resp.StatusCode)
	}
	var tok tokenResponse
	if err := decodeLimited(resp.Body, &tok); err != nil {
		return nil, errors.New("oauth: token endpoint answer is not a token response")
	}
	if tok.AccessToken == "" {
		return nil, errors.New("oauth: token endpoint gave no access token")
	}
	return &tok, nil
}

// userinfoResponse is the part of the userinfo answer the plugin reads.
type userinfoResponse struct {
	Sub, Email, Name, Picture string
	EmailVerified             bool
}

// userinfoWire is userinfoResponse as it arrives: email_verified may be a string.
type userinfoWire struct {
	Sub           string          `json:"sub"`
	Email         string          `json:"email"`
	Name          string          `json:"name"`
	Picture       string          `json:"picture"`
	EmailVerified json.RawMessage `json:"email_verified"`
}

// userinfo fetches the userinfo endpoint with the access token.
func (p *Plugin) userinfo(ctx context.Context, meta *metadata, accessToken string) (*userinfoResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, meta.UserinfoEndpoint, nil)
	if err != nil {
		return nil, errors.New("oauth: bad userinfo endpoint")
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")
	resp, err := p.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("oauth: userinfo endpoint: %w", stripURL(err))
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponse))
		return nil, fmt.Errorf("oauth: userinfo endpoint answered %d", resp.StatusCode)
	}
	var raw userinfoWire
	if err := decodeLimited(resp.Body, &raw); err != nil {
		return nil, errors.New("oauth: userinfo answer is not JSON")
	}
	verified, err := flexBool(raw.EmailVerified)
	if err != nil {
		return nil, err
	}
	return &userinfoResponse{Sub: raw.Sub, Email: raw.Email, Name: raw.Name, Picture: raw.Picture, EmailVerified: verified}, nil
}

// client is the HTTP client for provider calls.
func (p *Plugin) client() *http.Client {
	if p.opts.HTTPClient != nil {
		return p.opts.HTTPClient
	}
	return http.DefaultClient
}

// decodeLimited decodes one JSON value from at most maxResponse bytes of body.
func decodeLimited[T tokenResponse | userinfoWire](body io.Reader, v *T) error {
	return json.NewDecoder(io.LimitReader(body, maxResponse)).Decode(v)
}

// stripURL drops the request URL from a transport error, keeping what failed.
func stripURL(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}
