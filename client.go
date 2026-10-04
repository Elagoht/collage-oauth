package oauth

import (
	"container/list"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	// maxCached is how many opened tokens the memory cache holds; the oldest goes first.
	maxCached = 10_000
	// refreshWindow is how close to its expiry, in seconds, a token is refreshed.
	refreshWindow = 60
	// fetchTimeout bounds one load-and-refresh, which no single caller owns.
	fetchTimeout = 30 * time.Second
)

// tokenKey names one row: a user at a provider.
type tokenKey struct{ user, provider string }

// call is one load-and-refresh of a key, shared by every caller that asks for
// the key while it runs. token and err are written before done is closed.
type call struct {
	done  chan struct{}
	token string
	err   error
	retry bool // the call was superseded by a sign-in: its waiters ask again

	// Set under tokenState.mu by a hold (see hold): the result is not kept.
	revoked    bool // by Revoke: the waiters get ErrNotLinked
	superseded bool // by a sign-in: the waiters ask again once it is saved

	// handoff is what a superseded call would have saved, under mutex: the
	// sign-in saves instead, and keeps its refresh token when it has none.
	handoff stored
}

// hold keeps a key still while Revoke or a sign-in rewrites its row. While a
// hold exists no call starts for the key: token answers ErrNotLinked during a
// Revoke and waits for the hold to end during a sign-in. The call in flight when
// the first hold began is kept in c, so every holder, a later one too, waits for
// it before touching the row: whatever it saves lands first.
type hold struct {
	revokes, signIns int
	c                *call         // the call in flight when the hold began, or nil
	free             chan struct{} // closed when the last holder lets go
}

type cacheEntry struct {
	key tokenKey
	tok stored
}

// tokenState is the plugin's token memory. One mutex guards all of it, and it
// is never held across I/O (the store, the provider, discovery's own discMu),
// so it nests with no other lock.
type tokenState struct {
	mu      sync.Mutex
	entries map[tokenKey]*list.Element // of *cacheEntry, in order
	order   *list.List                 // insertion order, oldest at the front
	max     int                        // 0 is maxCached; tests lower it

	// signInWait bounds how long a sign-in waits for the call in flight before
	// it saves. 0 is fetchTimeout, by when the call has given up. Tests lower it.
	signInWait time.Duration

	// calls are the loads-and-refreshes in flight, one per key.
	calls map[tokenKey]*call
	// holds are the Revokes and sign-ins running, one hold per key. A hold is
	// removed when its last holder lets go, so the map stays as small as the
	// number of them running.
	holds map[tokenKey]*hold
}

// acquire takes a hold on k for a Revoke (revoke) or a sign-in, drops k's cached
// token, and marks the call in flight. It returns the call to wait for, or nil.
func (s *tokenState) acquire(k tokenKey, revoke bool) *call {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.drop(k)
	h := s.holds[k]
	if h == nil {
		h = &hold{free: make(chan struct{})}
		if s.holds == nil {
			s.holds = map[tokenKey]*hold{}
		}
		s.holds[k] = h
	}
	if c := s.calls[k]; c != nil {
		delete(s.calls, k)
		h.c = c
	}
	if revoke {
		h.revokes++
		if h.c != nil {
			h.c.revoked = true
		}
	} else {
		h.signIns++
		if h.c != nil {
			h.c.superseded = true
		}
	}
	return h.c
}

// release lets go of a hold taken by acquire, and drops k's cached token again.
func (s *tokenState) release(k tokenKey, revoke bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.drop(k)
	h := s.holds[k]
	if h == nil {
		return
	}
	if revoke {
		h.revokes--
	} else {
		h.signIns--
	}
	if h.revokes <= 0 && h.signIns <= 0 {
		delete(s.holds, k)
		close(h.free)
	}
}

// waitFor waits for c, when there is one, or for ctx.
func waitFor(ctx context.Context, c *call) error {
	if c == nil {
		return nil
	}
	select {
	case <-c.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// get returns the cached token of k. The caller holds mu.
func (s *tokenState) get(k tokenKey) (stored, bool) {
	if el, ok := s.entries[k]; ok {
		return el.Value.(*cacheEntry).tok, true
	}
	return stored{}, false
}

// put caches t for k: an update keeps its place, a new entry goes last and
// pushes the oldest out beyond the bound. The caller holds mu.
func (s *tokenState) put(k tokenKey, t stored) {
	if el, ok := s.entries[k]; ok {
		el.Value.(*cacheEntry).tok = t
		return
	}
	if s.entries == nil {
		s.entries, s.order = map[tokenKey]*list.Element{}, list.New()
	}
	limit := s.max
	if limit <= 0 {
		limit = maxCached
	}
	for s.order.Len() >= limit {
		oldest := s.order.Front()
		delete(s.entries, oldest.Value.(*cacheEntry).key)
		s.order.Remove(oldest)
	}
	s.entries[k] = s.order.PushBack(&cacheEntry{key: k, tok: t})
}

// drop forgets the cached token of k. The caller holds mu.
func (s *tokenState) drop(k tokenKey) {
	if el, ok := s.entries[k]; ok {
		delete(s.entries, k)
		s.order.Remove(el)
	}
}

// needsRefresh reports whether t has less than refreshWindow left. Expiry 0 is
// "the provider gave no lifetime": valid, never refreshed.
func needsRefresh(t stored, now int64) bool {
	return t.Expiry != 0 && t.Expiry-now < refreshWindow
}

// expired reports whether t's lifetime is over. Expiry 0 never is.
func expired(t stored, now int64) bool {
	return t.Expiry != 0 && now >= t.Expiry
}

// Client returns an *http.Client that sends the user's access token at the
// provider as a Bearer token. Every request asks for a valid token, refreshing
// it near expiry, so a Client kept for a long time keeps working.
//
// It returns ErrNotLinked up front when there is no usable token: no Store, no
// row, an expired token with no refresh token, or a refresh the provider
// refused with invalid_grant (the row is then deleted). The application can
// send the reader to sign in again. Any other error (the store, a provider
// outage with an expired token) comes back as it is.
//
// The returned client has no Timeout; the requests use Options.HTTPClient's
// Transport, or http.DefaultTransport.
func (p *Plugin) Client(ctx context.Context, userID, provider string) (*http.Client, error) {
	if _, err := p.token(ctx, userID, provider); err != nil {
		return nil, err
	}
	base := http.DefaultTransport
	if p.opts.HTTPClient != nil && p.opts.HTTPClient.Transport != nil {
		base = p.opts.HTTPClient.Transport
	}
	return &http.Client{Transport: &bearer{p: p, userID: userID, provider: provider, base: base}}, nil
}

// bearer is Client's transport.
type bearer struct {
	p                *Plugin
	userID, provider string
	base             http.RoundTripper
}

// errInsecureHost is the refusal to send a token in clear text.
var errInsecureHost = errors.New("oauth: Client refuses to send a token over plain http to a host other than loopback")

// RoundTrip sends a clone of req carrying the current access token.
//
// The token goes only where the first request went. On a redirect hop
// (req.Response is set), it is attached only when the hop's host is the first
// request's host or a subdomain of it, as net/http decides for the headers it
// copies itself, and the hop is not a downgrade from https. Any other hop is
// still followed, without the token. Plain http carries the token only to a
// loopback host; a first request elsewhere over http fails with errInsecureHost.
func (b *bearer) RoundTrip(req *http.Request) (*http.Response, error) {
	// Walk a redirect hop back to the first request. A hop whose chain breaks
	// (a Response without its Request) has no first request to compare with:
	// it fails closed, without the token.
	first := req
	for first != nil && first.Response != nil {
		first = first.Response.Request
	}
	attach := clearTextOK(req.URL)
	switch {
	case first == req:
		if !attach {
			closeBody(req)
			return nil, errInsecureHost
		}
	case first == nil:
		attach = false
	default:
		attach = attach && isDomainOrSubdomain(asciiLower(req.URL.Hostname()), asciiLower(first.URL.Hostname())) &&
			!(asciiLower(first.URL.Scheme) == "https" && asciiLower(req.URL.Scheme) != "https")
	}
	send := req
	if attach {
		tok, err := b.p.token(req.Context(), b.userID, b.provider)
		if err != nil {
			closeBody(req)
			return nil, err
		}
		send = req.Clone(req.Context())
		send.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := b.base.RoundTrip(send)
	if resp != nil && resp.Request == nil {
		// net/http's Client leaves this to the transport, and the next hop's
		// walk needs it; a custom transport may not fill it in. The request
		// without the token is enough to walk by.
		resp.Request = req
	}
	return resp, err
}

func closeBody(req *http.Request) {
	if req.Body != nil {
		_ = req.Body.Close()
	}
}

// clearTextOK reports whether u may carry a token: https, or http to loopback.
func clearTextOK(u *url.URL) bool {
	switch asciiLower(u.Scheme) {
	case "https":
		return true
	case "http":
		// By name only "localhost" itself; otherwise a loopback IP literal
		// (127.0.0.0/8, ::1).
		h := asciiLower(u.Hostname())
		if h == "localhost" {
			return true
		}
		ip := net.ParseIP(h)
		return ip != nil && ip.IsLoopback()
	}
	return false
}

// isDomainOrSubdomain reports whether sub is parent or a subdomain of it, as
// net/http's rule for copying sensitive headers on a redirect. An IPv6 address
// matches only itself.
func isDomainOrSubdomain(sub, parent string) bool {
	if sub == parent {
		return true
	}
	if strings.ContainsAny(sub, ":%") {
		return false
	}
	return strings.HasSuffix(sub, parent) && sub[len(sub)-len(parent)-1] == '.'
}

// asciiLower folds ASCII letters only.
func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}

// token returns a valid access token for the user at the provider: from the
// cache when it is not near expiry, otherwise through the key's one call in
// flight. A caller whose ctx ends stops waiting; the call goes on for the others.
func (p *Plugin) token(ctx context.Context, userID, name string) (string, error) {
	if p.opts.Store == nil {
		return "", ErrNotLinked
	}
	pr := p.providers[name]
	if pr == nil {
		return "", fmt.Errorf("oauth: unknown provider %q: %w", name, ErrNotLinked)
	}
	k := tokenKey{userID, name}
	for {
		tok, again, err := p.tokenOnce(ctx, k, pr)
		if !again {
			return tok, err
		}
	}
}

// tokenOnce is one try of token. again asks for another: a sign-in was rewriting
// the row, and the try waited for it.
func (p *Plugin) tokenOnce(ctx context.Context, k tokenKey, pr *provider) (tok string, again bool, err error) {
	now := p.clock().Unix()
	s := &p.tok
	s.mu.Lock()
	if h := s.holds[k]; h != nil {
		revoking, free := h.revokes > 0, h.free
		s.mu.Unlock()
		if revoking {
			return "", false, ErrNotLinked
		}
		select {
		case <-free:
			return "", true, nil
		case <-ctx.Done():
			return "", false, ctx.Err()
		}
	}
	if t, ok := s.get(k); ok {
		switch {
		case !needsRefresh(t, now):
			s.mu.Unlock()
			return t.AccessToken, false, nil
		case t.RefreshToken == "" && !expired(t, now):
			// Nothing to refresh with; it still works for a few seconds.
			s.mu.Unlock()
			return t.AccessToken, false, nil
		}
	}
	c := s.calls[k]
	if c == nil {
		c = &call{done: make(chan struct{})}
		if s.calls == nil {
			s.calls = map[tokenKey]*call{}
		}
		s.calls[k] = c
		go p.fetch(context.WithoutCancel(ctx), k, pr, c)
	}
	s.mu.Unlock()
	select {
	case <-c.done:
		return c.token, c.retry, c.err
	case <-ctx.Done():
		return "", false, ctx.Err()
	}
}

// fetch runs call c for k and publishes its result. The cache write and the
// call's removal happen in one critical section, so a caller arriving after it
// finds the cached token instead of starting a second refresh.
func (p *Plugin) fetch(ctx context.Context, k tokenKey, pr *provider, c *call) {
	ctx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()
	t, keep, err := p.load(ctx, k, pr, c)

	s := &p.tok
	s.mu.Lock()
	if s.calls[k] == c {
		delete(s.calls, k)
	}
	switch {
	case c.revoked:
		// Revoke started meanwhile: whatever this call saved, Revoke loads and
		// deletes after it, and nothing goes back in the cache.
		c.token, c.err = "", ErrNotLinked
	case c.superseded:
		// A sign-in saves after this call; the waiters ask again for its tokens.
		c.retry = true
	case err != nil:
		s.drop(k)
		c.err = err
	default:
		if keep {
			s.put(k, t)
		} else {
			s.drop(k)
		}
		c.token = t.AccessToken
	}
	s.mu.Unlock()
	close(c.done)
}

// load reads k's row, refreshes it when it is near expiry, and saves it again
// when it changed or was sealed with a previous key. keep reports whether the
// result may be cached.
func (p *Plugin) load(ctx context.Context, k tokenKey, pr *provider, c *call) (t stored, keep bool, err error) {
	store := p.opts.Store
	blob, err := store.Load(ctx, k.user, k.provider)
	if err != nil {
		return stored{}, false, fmt.Errorf("oauth: loading the token: %w", err)
	}
	if len(blob) == 0 {
		return stored{}, false, ErrNotLinked
	}
	t, current, err := p.open(k.user, k.provider, blob)
	if err != nil {
		return stored{}, false, ErrNotLinked
	}
	dirty := !current
	now := p.clock().Unix()
	if needsRefresh(t, now) && t.RefreshToken != "" {
		nt, err := p.refresh(ctx, pr, t)
		var te *tokenError
		switch {
		case err == nil:
			t, dirty = nt, true
		case errors.As(err, &te) && te.status == http.StatusBadRequest && te.code == "invalid_grant":
			// The grant is gone at the provider: so is the row, unless a hold
			// began meanwhile. A sign-in's row is newer than this grant, and a
			// Revoke deletes it anyway. The holder waits for this call, so the
			// check cannot go stale before the Delete lands.
			p.tok.mu.Lock()
			held := c.revoked || c.superseded
			p.tok.mu.Unlock()
			if !held {
				_ = store.Delete(ctx, k.user, k.provider)
			}
			return stored{}, false, ErrNotLinked
		case !expired(t, now):
			// An outage, but the token still works for a few seconds.
		default:
			return stored{}, false, err
		}
	}
	if expired(t, now) {
		return stored{}, false, ErrNotLinked
	}
	if dirty {
		// A sign-in that took over the key while this call ran saves its own
		// tokens, taking this call's refresh token over when it has none; were
		// its wait for this call to give up, this save must not land after it. (A revoked call still saves: Revoke always waits for it
		// and then revokes the newest refresh token.)
		p.tok.mu.Lock()
		superseded := c.superseded
		if superseded {
			c.handoff = t
		}
		p.tok.mu.Unlock()
		if superseded {
			return t, true, nil
		}
		stage := "sealing"
		blob, err := p.seal(k.user, k.provider, t)
		if err == nil {
			stage = "saving"
			err = store.Save(ctx, k.user, k.provider, blob)
		}
		if err != nil && p.host != nil {
			// The token in hand works, so it is still returned and cached.
			// Never err's text: a store's error may quote what it was given.
			p.host.Logger().Error("elagoht/oauth: keeping the refreshed tokens failed",
				"provider", k.provider, "user", k.user, "stage", stage)
		}
	}
	return t, true, nil
}

// refresh trades t's refresh token for new tokens. A response without a
// refresh token keeps t's, one without a scope keeps t's scopes.
func (p *Plugin) refresh(ctx context.Context, pr *provider, t stored) (stored, error) {
	meta, err := p.discover(ctx, pr)
	if err != nil {
		return stored{}, err
	}
	tr, err := p.tokenRequest(ctx, pr, meta, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {t.RefreshToken},
	})
	if err != nil {
		return stored{}, err
	}
	nt := stored{AccessToken: tr.AccessToken, RefreshToken: t.RefreshToken, Scopes: t.Scopes}
	if tr.RefreshToken != "" {
		nt.RefreshToken = tr.RefreshToken
	}
	if tr.ExpiresIn > 0 {
		nt.Expiry = p.clock().Unix() + tr.ExpiresIn
	}
	if scopes := strings.Fields(tr.Scope); len(scopes) > 0 {
		nt.Scopes = scopes
	}
	return nt, nil
}

// Revoke unlinks the user from the provider: it drops the cached token, asks
// the provider's revocation_endpoint (when discovery lists one) to revoke the
// refresh token, or the access token when there is none, and deletes the row.
//
// A load-and-refresh in flight for the user is waited for, and its result is
// neither cached nor handed out; whatever it saved is what Revoke revokes and
// deletes. While Revoke runs, Client for the user answers ErrNotLinked.
//
// It returns ErrNotLinked when there is nothing to revoke: no Store, an unknown
// provider, or no row. The row is deleted even when the provider's revocation
// fails; that error is returned after the deletion. If ctx ends while an
// in-flight call is waited for, Revoke returns ctx's error having deleted nothing.
func (p *Plugin) Revoke(ctx context.Context, userID, name string) error {
	store := p.opts.Store
	if store == nil {
		return ErrNotLinked
	}
	pr := p.providers[name]
	if pr == nil {
		return fmt.Errorf("oauth: unknown provider %q: %w", name, ErrNotLinked)
	}
	k := tokenKey{userID, name}
	c := p.tok.acquire(k, true)
	defer p.tok.release(k, true)
	if err := waitFor(ctx, c); err != nil {
		return err
	}
	blob, err := store.Load(ctx, userID, name)
	if err != nil {
		return fmt.Errorf("oauth: loading the token: %w", err)
	}
	if len(blob) == 0 {
		return ErrNotLinked
	}
	var revokeErr error
	if t, _, err := p.open(userID, name, blob); err == nil {
		revokeErr = p.revokeAtProvider(ctx, pr, t)
	}
	if err := store.Delete(ctx, userID, name); err != nil {
		return fmt.Errorf("oauth: deleting the token: %w", err)
	}
	return revokeErr
}

// revokeAtProvider posts t's refresh token, or its access token, to the
// revocation_endpoint (RFC 7009), with the same client authentication as the
// token endpoint. No endpoint is no error.
func (p *Plugin) revokeAtProvider(ctx context.Context, pr *provider, t stored) error {
	meta, err := p.discover(ctx, pr)
	if err != nil {
		return err
	}
	if meta.RevocationEndpoint == "" {
		return nil
	}
	form := url.Values{"token": {t.RefreshToken}, "token_type_hint": {"refresh_token"}}
	if t.RefreshToken == "" {
		form = url.Values{"token": {t.AccessToken}, "token_type_hint": {"access_token"}}
	}
	resp, err := p.authPost(ctx, pr, meta, meta.RevocationEndpoint, form)
	if err != nil {
		return fmt.Errorf("oauth: revocation endpoint: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponse))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("oauth: revocation endpoint answered %d", resp.StatusCode)
	}
	return nil
}
