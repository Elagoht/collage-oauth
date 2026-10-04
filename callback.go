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
	Scope        string `json:"scope"`
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

// signIn signs the session in as userID under a new session ID, so an ID planted
// before the sign-in holds nothing after it. A session that belongs to another
// user is cleared first, so nothing of theirs carries over; Set then starts it
// with a fresh ID. The same user signing in again keeps the session's data.
//
// If Set fails, userID is never stored. A session that belonged to another user
// has already been cleared, so it is signed out; one of the same user, or of no
// one, keeps what it held under its new ID.
func (p *Plugin) signIn(ctx context.Context, sess *session.Session, name, userID string, tok *tokenResponse) error {
	if prev := sess.Get(session.UserKey); prev != "" && prev != userID {
		sess.Clear()
	} else {
		sess.Regenerate()
	}
	if err := sess.Set(session.UserKey, userID); err != nil {
		return err
	}
	p.saveTokens(ctx, name, userID, tok)
	return nil
}

// saveTimeout bounds the Store call, which outlives the request.
const saveTimeout = 10 * time.Second

// saveTokens seals tok and hands it to the Store. A failure is logged without
// any token, and the sign-in still completes: the reader is signed in, only
// Client will answer ErrNotLinked until the next sign-in. The save does not
// share the request's cancellation: a browser that drops after the 303 must
// not lose the tokens.
func (p *Plugin) saveTokens(ctx context.Context, name, userID string, tok *tokenResponse) {
	if p.opts.Store == nil {
		return
	}
	ctx = context.WithoutCancel(ctx)
	scopes := strings.Fields(tok.Scope)
	if len(scopes) == 0 {
		scopes = requestedScopes(p.providers[name])
	}
	t := stored{AccessToken: tok.AccessToken, RefreshToken: tok.RefreshToken, Scopes: scopes}
	if tok.ExpiresIn > 0 {
		t.Expiry = p.clock().Unix() + tok.ExpiresIn
	}
	// A refresh in flight for this user saves before this sign-in does, never
	// after it, and its waiters ask again for these tokens; meanwhile no refresh
	// starts. Client's cache is dropped, so the earlier tokens are not handed out.
	// The wait comes first, so a rotation by that refresh is the one kept below.
	// The wait has its own bound, so the store calls below keep their full
	// saveTimeout whatever it took.
	k := tokenKey{userID, name}
	c := p.tok.acquire(k, false)
	defer p.tok.release(k, false)
	if c != nil {
		wait := p.tok.signInWait
		if wait <= 0 {
			wait = fetchTimeout
		}
		waitCtx, cancelWait := context.WithTimeout(ctx, wait)
		if waitFor(waitCtx, c) != nil {
			// The call cannot save after this: it checks for the sign-in first.
			p.host.Logger().Warn("elagoht/oauth: a refresh in flight outlasted the sign-in's wait", "provider", name, "user", userID)
		}
		cancelWait()
		p.tok.mu.Lock()
		if t.RefreshToken == "" {
			t.RefreshToken = c.handoff.RefreshToken
		}
		p.tok.mu.Unlock()
	}
	ctx, cancel := context.WithTimeout(ctx, saveTimeout)
	defer cancel()
	if t.RefreshToken == "" {
		// A sign-in that returns no refresh token keeps the one already stored.
		if old, err := p.opts.Store.Load(ctx, userID, name); err == nil && len(old) > 0 {
			if prev, _, err := p.open(userID, name, old); err == nil {
				t.RefreshToken = prev.RefreshToken
			}
		}
	}
	stage := "sealing"
	blob, err := p.seal(userID, name, t)
	if err == nil {
		stage = "saving"
		err = p.opts.Store.Save(ctx, userID, name, blob)
	}
	if err != nil {
		// Never err's text: a store's error may quote what it was given.
		p.host.Logger().Error("elagoht/oauth: keeping the tokens failed; the sign-in stands",
			"provider", name, "user", userID, "stage", stage, "canceled", errors.Is(err, context.Canceled))
	}
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

// tokenRequest POSTs form to the token endpoint with the client's credentials
// (see authPost). The answer must be a 200 of at most 1 MiB with an access
// token. Errors carry the status at most, never the body; a refusal is a
// *tokenError, whose code the caller may check.
func (p *Plugin) tokenRequest(ctx context.Context, pr *provider, meta *metadata, form url.Values) (*tokenResponse, error) {
	resp, err := p.authPost(ctx, pr, meta, meta.TokenEndpoint, form)
	if err != nil {
		return nil, fmt.Errorf("oauth: token endpoint: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(io.LimitReader(resp.Body, maxResponse)).Decode(&e)
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponse))
		return nil, &tokenError{status: resp.StatusCode, code: e.Error}
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

// tokenError is a token endpoint's refusal. Its text is the status only.
type tokenError struct {
	status int
	code   string // the answer's "error", when it had one
}

func (e *tokenError) Error() string {
	return fmt.Sprintf("oauth: token endpoint answered %d", e.status)
}

// authPost POSTs form to endpoint with the client's credentials, as RFC 6749
// 2.3.1 and RFC 7009 2.1 ask: HTTP Basic when the provider lists
// client_secret_basic or lists nothing, form fields otherwise. A transport
// error comes back without the request URL.
func (p *Plugin) authPost(ctx context.Context, pr *provider, meta *metadata, endpoint string, form url.Values) (*http.Response, error) {
	basic := len(meta.TokenAuthMethods) == 0 || slices.Contains(meta.TokenAuthMethods, "client_secret_basic")
	if !basic {
		form.Set("client_id", pr.cfg.ClientID)
		form.Set("client_secret", pr.secret)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, errors.New("bad endpoint")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if basic {
		// Both are form-encoded before Basic.
		req.SetBasicAuth(url.QueryEscape(pr.cfg.ClientID), url.QueryEscape(pr.secret))
	}
	resp, err := p.client().Do(req)
	if err != nil {
		return nil, stripURL(err)
	}
	return resp, nil
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
	return defaultHTTPClient
}

// defaultHTTPClient is used when Options.HTTPClient is nil (Configure sets one,
// so only a Plugin used without Configure gets here): never without a timeout.
var defaultHTTPClient = &http.Client{Timeout: 10 * time.Second}

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
